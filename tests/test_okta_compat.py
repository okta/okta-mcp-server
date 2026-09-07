# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Regression tests for :mod:`okta_mcp_server.utils.okta_compat`.

Each defect below was reproduced against okta==3.4.4 with a synthetic payload
before the shim existed; without ``apply_okta_model_compat()`` every "defect"
test here fails with a ``pydantic.ValidationError`` raised inside the SDK.

* **A** — ``SamlApplicationSettingsSignOn`` declares 5 required ``StrictBool``
  fields that the API often omits.
* **B** — ``Policy.embedded`` is typed ``Dict[str, Dict[str, Any]]`` but Okta
  returns scalars inside the ``_embedded`` HAL envelope.
* **C** — the authenticator ``key`` enum is closed and rejects ``smart_card_idp``.
* **D** — ``UserTypeCondition`` requires lists where Okta sends ``null``.

Control tests guard the other direction: fully-populated payloads must keep
their values, so the relaxation cannot be silently discarding data.
"""

from __future__ import annotations

import subprocess
import sys
import typing as t

import pytest

from okta_mcp_server.utils.okta_compat import (
    apply_okta_model_compat,
    relax_field,
    relax_field_everywhere,
)
from tests.conftest import load_fixture

# The shim mutates SDK classes process-wide.  Applying it at import keeps this
# module independent of test ordering; it is idempotent by design.
apply_okta_model_compat()


# ---------------------------------------------------------------------------
# Defect A — SamlApplicationSettingsSignOn required booleans
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "fixture_name",
    [
        # Keys absent entirely.  ``from_dict`` turns these into explicit None via
        # ``obj.get(...)`` -> "Input should be a valid boolean"; ``model_validate``
        # on the same payload reports "Field required".  Both must pass now.
        "saml_app_signon_missing_four_booleans.json",
        "saml_app_signon_missing_all_five_booleans.json",
        # Keys present, values explicitly null.
        "saml_app_signon_explicit_null_booleans.json",
    ],
)
def test_defect_a_saml_signon_missing_booleans_parse(fixture_name):
    """A SAML app whose ``settings.signOn`` omits/nulls the 5 booleans parses."""
    from okta.models.saml_application import SamlApplication

    app = SamlApplication.from_dict(load_fixture(fixture_name))

    assert app is not None
    sign_on = app.settings.sign_on
    assert sign_on.allow_multiple_acs_endpoints is None
    assert sign_on.assertion_signed is None
    assert sign_on.request_compressed is None
    assert sign_on.response_signed is None
    # Untouched fields still carry their values.
    assert sign_on.sso_acs_url == "https://sso.example.invalid/saml/acs"


def test_defect_a_covers_model_validate_entry_point():
    """The second entry point — ``model_validate`` on a payload missing the keys.

    ``from_dict`` and ``model_validate`` reported *different* errors for the same
    root cause (``bool_type`` vs ``missing``), so both are exercised.
    """
    from okta.models.saml_application_settings_sign_on import SamlApplicationSettingsSignOn

    assert SamlApplicationSettingsSignOn.model_validate({}).assertion_signed is None
    assert (
        SamlApplicationSettingsSignOn.model_validate({"assertionSigned": None}).assertion_signed
        is None
    )


def test_defect_a_control_populated_booleans_round_trip():
    """CONTROL: a fully-populated ``signOn`` keeps every boolean value."""
    from okta.models.saml_application import SamlApplication

    app = SamlApplication.from_dict(load_fixture("saml_app_signon_fully_populated.json"))

    sign_on = app.settings.sign_on
    assert sign_on.assertion_signed is True
    assert sign_on.response_signed is True
    assert sign_on.honor_force_authn is True
    # False must survive as False, not collapse to None.
    assert sign_on.allow_multiple_acs_endpoints is False
    assert sign_on.request_compressed is False


def test_defect_a_polymorphic_dispatch_still_routes_saml():
    """``Application.from_dict`` must still route ``SAML_2_0`` to ``SamlApplication``.

    The relaxation touches ``SamlApplicationSettingsSignOn``, which sits below the
    ``ApplicationJsonConverter`` dispatch on ``signOnMode``.  If a forced
    ``model_rebuild`` had disturbed that dispatch, list_applications would start
    handing back base ``Application`` objects with the SAML settings dropped.
    """
    from okta.models.application import Application
    from okta.models.saml_application import SamlApplication

    app = Application.from_dict(load_fixture("saml_app_signon_missing_four_booleans.json"))

    assert isinstance(app, SamlApplication)
    assert app.sign_on_mode.value == "SAML_2_0"
    assert app.label == "Example App"


# ---------------------------------------------------------------------------
# Defect B — narrow ``_embedded`` HAL envelope
# ---------------------------------------------------------------------------

def test_defect_b_access_policy_scalar_embedded_parses():
    """``{"_embedded": {"resourceType": "APP"}}`` no longer raises ``dict_type``."""
    from okta.models.access_policy import AccessPolicy

    policy = AccessPolicy.from_dict(load_fixture("access_policy_scalar_embedded.json"))

    assert policy.embedded == {"resourceType": "APP"}
    assert policy.id == "rst000000000000000000"


def test_defect_b_control_nested_embedded_still_parses():
    """CONTROL: the nested-object shape the model always accepted is preserved."""
    from okta.models.access_policy import AccessPolicy

    policy = AccessPolicy.from_dict(load_fixture("access_policy_nested_embedded.json"))

    assert policy.embedded == {"mappings": {"type": "APP", "id": "0oa000000000000000000"}}


def test_defect_b_patch_reaches_base_and_subclasses():
    """The patch must land on ``Policy`` *and* on each subclass's own FieldInfo.

    In Pydantic v2 a subclass gets its own ``model_fields`` dict holding its own
    ``FieldInfo``, so patching only the base class would leave every subclass
    broken.  This asserts the objects really are distinct and both were patched.
    """
    from okta.models.access_policy import AccessPolicy
    from okta.models.authenticator_enrollment_policy import AuthenticatorEnrollmentPolicy
    from okta.models.policy import Policy

    relaxed = t.Optional[t.Dict[str, t.Any]]
    assert Policy.model_fields["embedded"] is not AccessPolicy.model_fields["embedded"]
    for cls in (Policy, AccessPolicy, AuthenticatorEnrollmentPolicy):
        assert cls.model_fields["embedded"].annotation == relaxed, cls.__name__


def test_defect_b_subclass_created_after_patch_inherits_relaxation():
    """A ``Policy`` subclass defined *after* the shim ran also gets the relaxation.

    ``__subclasses__()`` can only sweep classes that already exist, so the shim
    also rewrites ``Policy.__annotations__``.  Pydantic collects inherited fields
    by walking the MRO's annotations, so any later subclass picks up the widened
    type without a second sweep.
    """
    from okta.models.policy import Policy

    class LatePolicy(Policy):
        """Stand-in for an SDK policy subclass imported after the shim ran."""

    assert LatePolicy.model_fields["embedded"].annotation == t.Optional[t.Dict[str, t.Any]]
    assert LatePolicy.model_validate(
        {"name": "Example", "type": "ACCESS_POLICY", "_embedded": {"resourceType": "APP"}}
    ).embedded == {"resourceType": "APP"}


_IMPORT_ORDER_SCRIPT = """
import json, sys
{first}
{second}
from okta.models.access_policy import AccessPolicy
payload = json.loads(sys.argv[1])
print(AccessPolicy.from_dict(payload).embedded["resourceType"])
"""

_IMPORT_SDK = "import okta.models.access_policy  # noqa: F401"
_IMPORT_SHIM = (
    "from okta_mcp_server.utils.okta_compat import apply_okta_model_compat; "
    "apply_okta_model_compat()"
)


@pytest.mark.parametrize(
    ("label", "first", "second"),
    [
        ("sdk imported before shim", _IMPORT_SDK, _IMPORT_SHIM),
        ("shim applied before sdk import", _IMPORT_SHIM, _IMPORT_SDK),
    ],
)
def test_defect_b_works_regardless_of_import_order(label, first, second):
    """``AccessPolicy`` is fixed whether it was imported before or after the shim.

    Run in a subprocess because import order can only be varied in a fresh
    interpreter.  The two halves of the patch cover the two orders: the
    ``model_fields`` sweep handles "already imported", the ``__annotations__``
    rewrite handles "imported later".
    """
    import json

    payload = load_fixture("access_policy_scalar_embedded.json")
    script = _IMPORT_ORDER_SCRIPT.format(first=first, second=second)

    proc = subprocess.run(
        [sys.executable, "-c", script, json.dumps(payload)],
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0, f"{label} failed:\n{proc.stderr}"
    assert proc.stdout.strip() == "APP", label


# ---------------------------------------------------------------------------
# Defect C — closed authenticator key enum
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("fixture_name", "expected_key"),
    [
        # PIV/CAC — a real authenticator type missing from the generated enum.
        ("mfa_enroll_policy_smart_card_idp.json", "smart_card_idp"),
        # Fictional: proves the fix is forward-compatible rather than a one-off
        # enum member addition that would break on the next new authenticator.
        ("mfa_enroll_policy_future_authenticator.json", "some_future_authenticator"),
    ],
)
def test_defect_c_unknown_authenticator_keys_parse(fixture_name, expected_key):
    from okta.models.authenticator_enrollment_policy import AuthenticatorEnrollmentPolicy

    policy = AuthenticatorEnrollmentPolicy.from_dict(load_fixture(fixture_name))

    keys = [a.key for a in policy.settings.authenticators]
    assert expected_key in keys
    assert all(isinstance(k, str) for k in keys)


def test_defect_c_known_authenticator_keys_still_parse():
    """CONTROL: keys that were always valid keep working and keep their value."""
    from okta.models.authenticator_enrollment_policy import AuthenticatorEnrollmentPolicy

    policy = AuthenticatorEnrollmentPolicy.from_dict(
        load_fixture("mfa_enroll_policy_smart_card_idp.json")
    )

    assert policy.settings.authenticators[0].key == "okta_password"


# ---------------------------------------------------------------------------
# Defect D — required lists on condition models
# ---------------------------------------------------------------------------

def test_defect_d_null_user_type_condition_parses():
    """``{"userType": {"exclude": null, "include": null}}`` — BOTH fields failed."""
    from okta.models.access_policy_rule import AccessPolicyRule

    rule = AccessPolicyRule.from_dict(load_fixture("access_policy_rule_null_user_type.json"))

    assert rule.conditions.user_type.exclude is None
    assert rule.conditions.user_type.include is None


def test_defect_d_control_explicit_lists_are_not_coerced_to_none():
    """CONTROL: an explicit ``[]`` must stay ``[]`` and never become ``None``.

    Relaxing a required field to ``Optional[...] = None`` risks conflating "empty"
    with "absent"; downstream policy logic treats those very differently.
    """
    from okta.models.access_policy_rule import AccessPolicyRule

    rule = AccessPolicyRule.from_dict(load_fixture("access_policy_rule_empty_user_type.json"))

    user_type = rule.conditions.user_type
    assert user_type.exclude == []
    assert user_type.exclude is not None
    assert user_type.include == ["otyp00000000000000000"]


def test_defect_d_sibling_condition_models_also_relaxed():
    """The two sibling condition models with the same over-strict shape."""
    from okta.models.risk_detection_types_policy_rule_condition import (
        RiskDetectionTypesPolicyRuleCondition,
    )
    from okta.models.user_identifier_policy_rule_condition import (
        UserIdentifierPolicyRuleCondition,
    )

    risk = RiskDetectionTypesPolicyRuleCondition.model_validate({"exclude": None, "include": None})
    assert risk.exclude is None and risk.include is None

    identifier = UserIdentifierPolicyRuleCondition.model_validate(
        {"type": "IDENTIFIER", "patterns": None}
    )
    assert identifier.patterns is None


def test_already_optional_sibling_conditions_untouched():
    """Sibling models that were already correct must not have been patched.

    Listed in the brief as explicitly out of scope; asserting it keeps a future
    edit from over-reaching into models that never had the defect.
    """
    from okta.models.group_condition import GroupCondition
    from okta.models.user_condition import UserCondition

    for cls in (GroupCondition, UserCondition):
        for name in ("exclude", "include"):
            if name in cls.model_fields:
                assert not cls.model_fields[name].is_required(), f"{cls.__name__}.{name}"


# ---------------------------------------------------------------------------
# LogSecurityContext — migrated from tools/system_logs/system_logs.py
# ---------------------------------------------------------------------------

def test_log_security_context_user_behaviors_accepts_dicts():
    """The migrated patch keeps its original behavior: ``List[dict]`` is accepted.

    With Behavior Detection enabled the API returns ``userBehaviors`` as a list of
    objects while the generated model declares ``List[StrictStr]``.
    """
    from okta.models.log_security_context import LogSecurityContext

    ctx = LogSecurityContext.model_validate(
        {"userBehaviors": [{"name": "NEW_DEVICE", "outcome": "POSITIVE"}]}
    )
    assert ctx.user_behaviors == [{"name": "NEW_DEVICE", "outcome": "POSITIVE"}]


def test_system_logs_module_no_longer_patches_inline():
    """``system_logs.py`` must delegate to the shim rather than re-patching inline."""
    import pathlib

    import okta_mcp_server.tools.system_logs.system_logs as system_logs

    source = pathlib.Path(system_logs.__file__).read_text()
    assert "apply_okta_model_compat" in source
    assert "_LogSecurityContext" not in source


# ---------------------------------------------------------------------------
# Helper behavior
# ---------------------------------------------------------------------------

def test_relax_field_returns_false_for_unknown_field():
    """A field that no longer exists is reported, not raised — future SDK safety."""
    from okta.models.user_type_condition import UserTypeCondition

    assert relax_field(UserTypeCondition, "field_that_does_not_exist", t.Optional[str]) is False


def test_relax_field_makes_required_field_optional():
    """Setting ``.default`` — not just ``.annotation`` — is what drops "required"."""
    from pydantic import BaseModel

    class Sample(BaseModel):
        flag: bool

    assert Sample.model_fields["flag"].is_required()
    assert relax_field(Sample, "flag", t.Optional[bool]) is True
    assert not Sample.model_fields["flag"].is_required()
    assert Sample.model_validate({}).flag is None
    assert Sample.model_validate({"flag": None}).flag is None
    assert Sample.model_validate({"flag": True}).flag is True


def test_relax_field_everywhere_patches_subclass_tree():
    from pydantic import BaseModel

    class Base(BaseModel):
        value: str

    class Middle(Base):
        pass

    class Leaf(Middle):
        pass

    patched = relax_field_everywhere(Base, "value", t.Optional[str])

    assert set(patched) == {"Base", "Middle", "Leaf"}
    for cls in (Base, Middle, Leaf):
        assert cls.model_validate({}).value is None


def test_apply_okta_model_compat_is_idempotent():
    """Calling twice must not raise and must leave the relaxations in place."""
    from okta.models.access_policy import AccessPolicy

    apply_okta_model_compat()
    apply_okta_model_compat()

    assert AccessPolicy.from_dict(load_fixture("access_policy_scalar_embedded.json")).embedded == {
        "resourceType": "APP"
    }


def test_one_failing_patch_does_not_block_the_others(monkeypatch):
    """A patch that raises logs a warning; the remaining patches still apply."""
    import okta_mcp_server.utils.okta_compat as compat

    def _boom() -> str:
        raise RuntimeError("simulated future-SDK breakage")

    monkeypatch.setattr(
        compat,
        "_PATCHES",
        (("exploding patch", _boom), *compat._PATCHES),
    )

    compat.apply_okta_model_compat()  # must not raise

    from okta.models.access_policy import AccessPolicy

    assert AccessPolicy.model_fields["embedded"].annotation == t.Optional[t.Dict[str, t.Any]]
