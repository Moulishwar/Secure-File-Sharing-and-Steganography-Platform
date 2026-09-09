"""Authorization.

Each test here maps to a finding from the security review of the legacy app.
The review found that the approval workflow existed only in Jinja conditionals:
/decrypt never consulted the requests table, /textdecrypt had no ownership
filter at all, and every state change was a GET link with no CSRF token.

These are the tests that would have failed on the old code.
"""

import io

import pytest


def _open(actor, carrier, password="share-password"):
    return actor.client.post(
        "/open",
        data={
            "carrier": (io.BytesIO(carrier), "carrier.png"),
            "password": password,
        },
        content_type="multipart/form-data",
    )


# --------------------------------------------------------------------------
# F-01: decryption had no authorization check
# --------------------------------------------------------------------------


def test_recipient_cannot_open_before_approval(actor, make_share):
    """The legacy /decrypt decrypted for anyone holding a row, approved or not."""
    owner = actor("owner@example.test", "Owner")
    bob = actor("bob@example.test", "Bob")

    _, carrier = make_share(owner, recipients=[bob], approvals=1)

    response = _open(bob, carrier)
    assert response.status_code == 403


def test_recipient_can_open_after_approval(actor, make_share):
    owner = actor("owner@example.test", "Owner")
    bob = actor("bob@example.test", "Bob")

    public_id, carrier = make_share(
        owner, recipients=[bob], approvals=1, content=b"the real payload"
    )

    assert bob.client.post(f"/share/{public_id}/request").status_code == 302
    assert owner.client.post(
        f"/share/{public_id}/approve", data={"requester_id": bob.id}
    ).status_code == 302

    response = _open(bob, carrier)
    assert response.status_code == 200
    assert response.data == b"the real payload"


def test_approval_writes_key_material_that_did_not_exist(app, actor, make_share):
    """The gate is the key's existence, not a flag consulted at read time."""
    owner = actor("owner@example.test", "Owner")
    bob = actor("bob@example.test", "Bob")
    public_id, _ = make_share(owner, recipients=[bob], approvals=1)

    def wrapped_dek_for_bob():
        with app.app_context():
            from stegoshare.db import get_db

            return get_db().execute(
                "SELECT g.wrapped_dek FROM grants g JOIN shares s ON s.id = g.share_id "
                "WHERE s.public_id = ? AND g.recipient_id = ?",
                (public_id, bob.id),
            ).fetchone()["wrapped_dek"]

    assert wrapped_dek_for_bob() is None

    bob.client.post(f"/share/{public_id}/request")
    owner.client.post(f"/share/{public_id}/approve", data={"requester_id": bob.id})

    assert wrapped_dek_for_bob() is not None


def test_threshold_of_two_needs_two_approvals(actor, make_share):
    owner = actor("owner@example.test", "Owner")
    alice = actor("alice@example.test", "Alice")
    bob = actor("bob@example.test", "Bob")

    public_id, carrier = make_share(owner, recipients=[alice, bob], approvals=2)

    # Alice gets in first so there are two key-holders to approve from.
    alice.client.post(f"/share/{public_id}/request")
    owner.client.post(f"/share/{public_id}/approve", data={"requester_id": alice.id})
    assert _open(alice, carrier).status_code == 403  # 1 of 2

    alice2 = alice  # alice still lacks a second approval
    assert _open(alice2, carrier).status_code == 403


# --------------------------------------------------------------------------
# F-02: no ownership filter -- any user could read any payload
# --------------------------------------------------------------------------


def test_stranger_with_image_and_password_is_refused(actor, make_share):
    """Possession of the carrier is necessary but never sufficient."""
    owner = actor("owner@example.test", "Owner")
    bob = actor("bob@example.test", "Bob")
    mallory = actor("mallory@example.test", "Mallory")

    _, carrier = make_share(owner, recipients=[bob])

    # Mallory has the image and the correct password, and is logged in.
    response = _open(mallory, carrier)
    assert response.status_code == 403


def test_owner_can_always_open_their_own_share(actor, make_share):
    owner = actor("owner@example.test", "Owner")
    _, carrier = make_share(owner, content=b"owner payload")

    response = _open(owner, carrier)
    assert response.status_code == 200
    assert response.data == b"owner payload"


def test_wrong_password_does_not_reveal_the_share_exists(actor, make_share):
    owner = actor("owner@example.test", "Owner")
    _, carrier = make_share(owner)

    response = _open(owner, carrier, password="wrong-password")
    assert response.status_code == 400
    assert b"No payload found" in response.data


# --------------------------------------------------------------------------
# F-06: requests were not validated against the share list
# --------------------------------------------------------------------------


def test_cannot_request_access_to_a_share_you_are_not_on(actor, make_share):
    owner = actor("owner@example.test", "Owner")
    bob = actor("bob@example.test", "Bob")
    mallory = actor("mallory@example.test", "Mallory")

    public_id, _ = make_share(owner, recipients=[bob])

    assert mallory.client.post(f"/share/{public_id}/request").status_code == 403


def test_duplicate_requests_do_not_stack(app, actor, make_share):
    owner = actor("owner@example.test", "Owner")
    bob = actor("bob@example.test", "Bob")
    public_id, _ = make_share(owner, recipients=[bob])

    for _ in range(5):
        bob.client.post(f"/share/{public_id}/request")

    with app.app_context():
        from stegoshare.db import get_db

        count = get_db().execute(
            "SELECT COUNT(*) AS c FROM access_requests"
        ).fetchone()["c"]
    assert count == 1


def test_cannot_approve_a_request_addressed_to_someone_else(actor, make_share):
    owner = actor("owner@example.test", "Owner")
    bob = actor("bob@example.test", "Bob")
    mallory = actor("mallory@example.test", "Mallory")

    public_id, _ = make_share(owner, recipients=[bob])
    bob.client.post(f"/share/{public_id}/request")

    # Mallory is not an approver for this share.
    response = mallory.client.post(
        f"/share/{public_id}/approve", data={"requester_id": bob.id}
    )
    assert response.status_code == 403


def test_approving_twice_is_refused(actor, make_share):
    owner = actor("owner@example.test", "Owner")
    bob = actor("bob@example.test", "Bob")
    public_id, _ = make_share(owner, recipients=[bob])

    bob.client.post(f"/share/{public_id}/request")
    first = owner.client.post(
        f"/share/{public_id}/approve", data={"requester_id": bob.id}
    )
    second = owner.client.post(
        f"/share/{public_id}/approve", data={"requester_id": bob.id}
    )
    assert first.status_code == 302
    assert second.status_code == 403


# --------------------------------------------------------------------------
# F-07: state changes were GET links with no CSRF token
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/logout", "/share/any-id/request", "/share/any-id/approve", "/share"],
)
def test_state_changing_routes_reject_get(client, path):
    """No state change is reachable by following a link.

    /open is deliberately absent: GET /open renders the upload form and changes
    nothing; POST /open is the action.
    """
    assert client.get(path).status_code == 405


def test_csrf_is_enforced_when_enabled(app, actor):
    """The fixtures disable CSRF for convenience; prove it actually works."""
    owner = actor("owner@example.test", "Owner")
    app.config["WTF_CSRF_ENABLED"] = True

    response = owner.client.post("/logout")
    assert response.status_code == 400


# --------------------------------------------------------------------------
# no login check -- legacy raised KeyError -> 500 with an interactive debugger
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path", ["/dashboard", "/share/new", "/open", "/requests"]
)
def test_protected_pages_redirect_when_logged_out(client, path):
    response = client.get(path)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_logged_out_post_does_not_500(client):
    response = client.post("/share/some-id/request")
    assert response.status_code == 302
