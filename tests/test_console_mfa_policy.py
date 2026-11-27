"""R-07 in the console (0.41.0): the organization two-factor policy and the
policy-forced enrolment. Text guards, like the other console tests."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = (ROOT / "frontend/console/app.js").read_text(encoding="utf-8")


def test_the_policy_card_reads_and_writes_the_policy_route():
    assert "get('/mfa-policy')" in APP
    assert "put('/mfa-policy', { require_mfa: !st.require_mfa })" in APP
    assert "await mfaPolicyCard($('#mfa-policy-card'))" in APP


def test_an_enrolment_only_sign_in_goes_to_the_set_up_screen_not_the_app():
    login = APP[APP.index("await api('/auth/login'"):]
    login = login[:login.index("const me = await get('/auth/me')")]
    assert "if (tok.mfa_enrollment_required) { enrolmentScreen(); return; }" in login


def test_the_enrolment_survives_a_reload_and_a_logout_forgets_it():
    assert "localStorage.getItem('veyrs.enroll') === '1'" in APP
    assert "['at', 'rt', 'perms', 'enroll']" in APP


def test_activation_hands_over_the_full_token_pair():
    assert "a.tokens ? () => finishEnrolment(a.tokens) : null" in APP
    fin = APP[APP.index("async function finishEnrolment"):]
    assert "store.save(tokens)" in fin[:400] and "enterApp(" in fin[:400]
