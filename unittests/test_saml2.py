from unittest.mock import Mock, patch

from django.test import override_settings

from dojo.models import Dojo_Group, Dojo_Group_Member, Role, User
from dojo.authorization.roles_permissions import Roles

from .dojo_test_case import DojoTestCase


class TestSaml2Backend(DojoTestCase):
    """
    Test suite for the custom SAML2 backend with group mapping functionality.
    
    These tests verify that:
    - Users are automatically assigned to groups based on SAML assertions
    - Groups are created if they don't exist
    - Group memberships are cleaned up when users are removed from groups
    - Regex filtering works correctly
    - The backend handles various edge cases properly
    """

    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create a test user
        self.user, _ = User.objects.get_or_create(
            username="saml_test_user",
            first_name="SAML",
            last_name="Test",
            email="saml@example.com",
        )
        
        # Create pre-existing groups
        self.existing_group1, _ = Dojo_Group.objects.get_or_create(
            name="existing_group_1",
            social_provider=Dojo_Group.SAML
        )
        self.existing_group2, _ = Dojo_Group.objects.get_or_create(
            name="existing_group_2",
            social_provider=Dojo_Group.SAML
        )
        
        # Create a group from a different provider to ensure cleanup doesn't affect it
        self.azure_group, _ = Dojo_Group.objects.get_or_create(
            name="azure_group",
            social_provider=Dojo_Group.AZURE
        )

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="",
    )
    @patch('dojo.backends.Saml2Backend._update_user')
    def test_group_mapping_creates_new_groups(self, mock_super_update_user):
        """Test that new groups are created when they don't exist."""
        from dojo.backends import Saml2Backend
        
        # Mock parent's _update_user to return the user
        mock_super_update_user.return_value = self.user
        
        backend = Saml2Backend()
        
        # Simulate SAML attributes with new groups
        attributes = {
            "groups": ["new_group_1", "new_group_2", "new_group_3"]
        }
        attribute_mapping = {}
        
        # Manually call _process_user_groups since we're testing it directly
        backend._process_user_groups(self.user, attributes)
        
        # Verify new groups were created
        self.assertTrue(Dojo_Group.objects.filter(name="new_group_1", social_provider=Dojo_Group.SAML).exists())
        self.assertTrue(Dojo_Group.objects.filter(name="new_group_2", social_provider=Dojo_Group.SAML).exists())
        self.assertTrue(Dojo_Group.objects.filter(name="new_group_3", social_provider=Dojo_Group.SAML).exists())
        
        # Verify user is member of all groups
        memberships = Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML)
        self.assertEqual(memberships.count(), 3)
        
        # Verify the role is set correctly (should be Maintainer based on pipeline.py)
        for membership in memberships:
            self.assertEqual(membership.role.id, Roles.Maintainer)

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="",
    )
    def test_group_mapping_adds_to_existing_groups(self):
        """Test that users are added to existing groups."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        # Simulate SAML attributes with existing groups
        attributes = {
            "groups": [self.existing_group1.name, self.existing_group2.name]
        }
        
        backend._process_user_groups(self.user, attributes)
        
        # Verify user is member of both existing groups
        memberships = Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML)
        self.assertEqual(memberships.count(), 2)
        
        # Verify the groups themselves exist
        self.assertTrue(memberships.filter(group=self.existing_group1).exists())
        self.assertTrue(memberships.filter(group=self.existing_group2).exists())

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="",
    )
    def test_group_cleanup_removes_old_memberships(self):
        """Test that old SAML group memberships are removed when user is no longer in those groups."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        # First login: add user to group1 and group2
        attributes_initial = {
            "groups": [self.existing_group1.name, self.existing_group2.name]
        }
        backend._process_user_groups(self.user, attributes_initial)
        
        # Verify user is in both groups
        self.assertEqual(
            Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML).count(),
            2
        )
        
        # Second login: user is now only in group1
        attributes_updated = {
            "groups": [self.existing_group1.name]
        }
        backend._process_user_groups(self.user, attributes_updated)
        
        # Verify user is only in group1 now
        memberships = Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML)
        self.assertEqual(memberships.count(), 1)
        self.assertEqual(memberships.first().group.name, self.existing_group1.name)

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="",
    )
    def test_cleanup_preserves_non_saml_groups(self):
        """Test that cleanup doesn't remove memberships from non-SAML groups."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        # Add user to an Azure AD group manually
        Dojo_Group_Member.objects.create(
            user=self.user,
            group=self.azure_group,
            role=Role.objects.get(id=Roles.Maintainer)
        )
        
        # Login with SAML groups
        attributes = {
            "groups": [self.existing_group1.name]
        }
        backend._process_user_groups(self.user, attributes)
        
        # Verify user is in both SAML group and Azure group
        saml_memberships = Dojo_Group_Member.objects.filter(
            user=self.user,
            group__social_provider=Dojo_Group.SAML
        )
        azure_memberships = Dojo_Group_Member.objects.filter(
            user=self.user,
            group__social_provider=Dojo_Group.AZURE
        )
        
        self.assertEqual(saml_memberships.count(), 1)
        self.assertEqual(azure_memberships.count(), 1)
        self.assertEqual(azure_memberships.first().group.name, self.azure_group.name)

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="^DOJO_.*",
    )
    def test_group_filter_regex(self):
        """Test that group filtering with regex works correctly."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        # Simulate SAML attributes with mix of matching and non-matching groups
        attributes = {
            "groups": [
                "DOJO_Developers",
                "DOJO_Admins",
                "IT_Team",
                "HR_Group",
                "DOJO_Readers",
            ]
        }
        
        backend._process_user_groups(self.user, attributes)
        
        # Verify only groups matching the regex were created
        saml_groups = Dojo_Group.objects.filter(social_provider=Dojo_Group.SAML)
        group_names = [g.name for g in saml_groups]
        
        self.assertIn("DOJO_Developers", group_names)
        self.assertIn("DOJO_Admins", group_names)
        self.assertIn("DOJO_Readers", group_names)
        self.assertNotIn("IT_Team", group_names)
        self.assertNotIn("HR_Group", group_names)
        
        # Verify user is only member of filtered groups
        memberships = Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML)
        self.assertEqual(memberships.count(), 3)

    @override_settings(
        SAML2_ENABLED=False,
        SAML2_GROUPS_ATTRIBUTE="groups",
    )
    def test_group_mapping_disabled_when_saml_disabled(self):
        """Test that group mapping doesn't run when SAML is disabled."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        # group_re should be None when SAML is disabled
        self.assertIsNone(backend.group_re)
        
        # Process should not create groups
        attributes = {
            "groups": ["test_group"]
        }
        backend._process_user_groups(self.user, attributes)
        
        # No groups should be created
        self.assertFalse(Dojo_Group.objects.filter(name="test_group").exists())

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="",
        SAML2_GROUPS_FILTER="",
    )
    def test_group_mapping_disabled_when_no_attribute(self):
        """Test that group mapping doesn't run when SAML2_GROUPS_ATTRIBUTE is empty."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        # group_re should be None when GROUPS_ATTRIBUTE is empty
        self.assertIsNone(backend.group_re)

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="",
    )
    def test_single_group_as_string(self):
        """Test that a single group provided as string (not list) is handled correctly."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        # Some IdPs might send a single group as a string instead of a list
        attributes = {
            "groups": "single_group"
        }
        
        backend._process_user_groups(self.user, attributes)
        
        # Verify the group was created and user is member
        self.assertTrue(Dojo_Group.objects.filter(name="single_group", social_provider=Dojo_Group.SAML).exists())
        self.assertTrue(
            Dojo_Group_Member.objects.filter(
                user=self.user,
                group__name="single_group"
            ).exists()
        )

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="memberOf",
        SAML2_GROUPS_FILTER="",
    )
    def test_different_attribute_name(self):
        """Test that different SAML attribute names work (e.g., 'memberOf' instead of 'groups')."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        # Use 'memberOf' instead of 'groups' (common in AD/LDAP)
        attributes = {
            "memberOf": ["CN=Group1,OU=Users,DC=example,DC=com", "CN=Group2,OU=Users,DC=example,DC=com"]
        }
        
        backend._process_user_groups(self.user, attributes)
        
        # Verify groups were created
        self.assertTrue(
            Dojo_Group.objects.filter(
                name="CN=Group1,OU=Users,DC=example,DC=com",
                social_provider=Dojo_Group.SAML
            ).exists()
        )

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="",
    )
    def test_empty_groups_attribute(self):
        """Test that empty groups attribute doesn't cause errors."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        # Test with empty list
        attributes = {
            "groups": []
        }
        backend._process_user_groups(self.user, attributes)
        
        # No groups should be created
        memberships = Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML)
        self.assertEqual(memberships.count(), 0)

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="",
    )
    def test_missing_groups_attribute(self):
        """Test that missing groups attribute doesn't cause errors."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        # Test with no groups attribute at all
        attributes = {
            "email": "test@example.com"
        }
        backend._process_user_groups(self.user, attributes)
        
        # No groups should be created
        memberships = Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML)
        self.assertEqual(memberships.count(), 0)

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="^(Admin|Developer)_.*",
    )
    def test_complex_regex_filter(self):
        """Test complex regex patterns for group filtering."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        # Test with groups matching: Admin_* or Developer_*
        attributes = {
            "groups": [
                "Admin_Global",
                "Developer_Frontend",
                "Developer_Backend",
                "Viewer_ReadOnly",
                "Guest_External",
            ]
        }
        
        backend._process_user_groups(self.user, attributes)
        
        # Verify only matching groups were created
        saml_groups = Dojo_Group.objects.filter(social_provider=Dojo_Group.SAML).values_list('name', flat=True)
        
        self.assertIn("Admin_Global", saml_groups)
        self.assertIn("Developer_Frontend", saml_groups)
        self.assertIn("Developer_Backend", saml_groups)
        self.assertNotIn("Viewer_ReadOnly", saml_groups)
        self.assertNotIn("Guest_External", saml_groups)
        
        # Verify user has 3 memberships
        memberships = Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML)
        self.assertEqual(memberships.count(), 3)

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="",
    )
    def test_idempotent_group_assignment(self):
        """Test that assigning the same groups multiple times doesn't create duplicates."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        attributes = {
            "groups": ["group_a", "group_b"]
        }
        
        # Process groups twice
        backend._process_user_groups(self.user, attributes)
        backend._process_user_groups(self.user, attributes)
        
        # Verify there are still only 2 groups and 2 memberships
        groups = Dojo_Group.objects.filter(social_provider=Dojo_Group.SAML)
        memberships = Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML)
        
        self.assertEqual(groups.count(), 2)
        self.assertEqual(memberships.count(), 2)

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="",
    )
    def test_full_group_rotation(self):
        """Test complete group rotation scenario."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        # First login: user gets group1 and group2
        attributes_1 = {
            "groups": ["rotation_group_1", "rotation_group_2"]
        }
        backend._process_user_groups(self.user, attributes_1)
        memberships = Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML)
        self.assertEqual(memberships.count(), 2)
        
        # Second login: user gets group2 and group3 (group1 removed, group3 added)
        attributes_2 = {
            "groups": ["rotation_group_2", "rotation_group_3"]
        }
        backend._process_user_groups(self.user, attributes_2)
        memberships = Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML)
        self.assertEqual(memberships.count(), 2)
        self.assertTrue(memberships.filter(group__name="rotation_group_2").exists())
        self.assertTrue(memberships.filter(group__name="rotation_group_3").exists())
        self.assertFalse(memberships.filter(group__name="rotation_group_1").exists())
        
        # Third login: user gets completely new groups
        attributes_3 = {
            "groups": ["rotation_group_4", "rotation_group_5"]
        }
        backend._process_user_groups(self.user, attributes_3)
        memberships = Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML)
        self.assertEqual(memberships.count(), 2)
        self.assertTrue(memberships.filter(group__name="rotation_group_4").exists())
        self.assertTrue(memberships.filter(group__name="rotation_group_5").exists())

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER=".*",
    )
    def test_match_all_regex(self):
        """Test that '.*' regex matches all groups."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        attributes = {
            "groups": ["any_group", "123-numbers", "special!chars", "CamelCase"]
        }
        
        backend._process_user_groups(self.user, attributes)
        
        # All groups should be created
        memberships = Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML)
        self.assertEqual(memberships.count(), 4)

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="",
    )
    def test_group_re_cached_property(self):
        """Test that group_re is cached and compiled once."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        # Access group_re multiple times
        regex1 = backend.group_re
        regex2 = backend.group_re
        
        # Should be the same object (cached)
        self.assertIs(regex1, regex2)
        
        # Should be a compiled regex pattern
        import re
        self.assertIsInstance(regex1, re.Pattern)

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="",
    )
    def test_update_user_integration(self):
        """Test the full _update_user flow with group processing."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        # Create a mock for the parent's _update_user
        with patch.object(backend.__class__.__bases__[0], '_update_user', return_value=self.user):
            attributes = {
                "email": ("test@example.com",),
                "username": ("saml_test_user",),
                "groups": ["integration_group_1", "integration_group_2"]
            }
            attribute_mapping = {
                "email": "email",
                "username": "username"
            }
            
            result_user = backend._update_user(self.user, attributes, attribute_mapping, force_save=False)
            
            # Verify user was returned
            self.assertEqual(result_user, self.user)
            
            # Verify groups were processed
            memberships = Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML)
            self.assertEqual(memberships.count(), 2)

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="(?i)^defectdojo.*",  # Case-insensitive
    )
    def test_case_insensitive_regex(self):
        """Test case-insensitive regex filtering."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        attributes = {
            "groups": ["DefectDojo-Admins", "defectdojo-users", "DEFECTDOJO-VIEWERS", "Other-Group"]
        }
        
        backend._process_user_groups(self.user, attributes)
        
        # Verify case-insensitive matching worked
        saml_groups = Dojo_Group.objects.filter(social_provider=Dojo_Group.SAML).values_list('name', flat=True)
        
        self.assertIn("DefectDojo-Admins", saml_groups)
        self.assertIn("defectdojo-users", saml_groups)
        self.assertIn("DEFECTDOJO-VIEWERS", saml_groups)
        self.assertNotIn("Other-Group", saml_groups)

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="",
    )
    def test_special_characters_in_group_names(self):
        """Test that group names with special characters are handled correctly."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        attributes = {
            "groups": [
                "Group-With-Dashes",
                "Group_With_Underscores",
                "Group.With.Dots",
                "Group (With Parens)",
            ]
        }
        
        backend._process_user_groups(self.user, attributes)
        
        # Verify all groups were created
        memberships = Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML)
        self.assertEqual(memberships.count(), 4)

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="",
    )
    def test_error_handling_in_group_processing(self):
        """Test that errors in group processing don't break authentication."""
        from dojo.backends import Saml2Backend
        
        backend = Saml2Backend()
        
        # Test with invalid attribute structure that might cause errors
        attributes = {
            "groups": None  # This might cause issues
        }
        
        # Should not raise exception
        try:
            backend._process_user_groups(self.user, attributes)
        except Exception as e:
            self.fail(f"Group processing should not raise exceptions: {e}")

    @override_settings(
        SAML2_ENABLED=True,
        SAML2_GROUPS_ATTRIBUTE="groups",
        SAML2_GROUPS_FILTER="",
    )
    def test_multiple_users_same_groups(self):
        """Test that multiple users can be in the same SAML groups."""
        from dojo.backends import Saml2Backend
        
        # Create a second user
        user2, _ = User.objects.get_or_create(
            username="saml_test_user_2",
            email="saml2@example.com",
        )
        
        backend = Saml2Backend()
        
        attributes = {
            "groups": ["shared_group_1", "shared_group_2"]
        }
        
        # Process for both users
        backend._process_user_groups(self.user, attributes)
        backend._process_user_groups(user2, attributes)
        
        # Verify both users are in the same groups
        user1_memberships = Dojo_Group_Member.objects.filter(user=self.user, group__social_provider=Dojo_Group.SAML)
        user2_memberships = Dojo_Group_Member.objects.filter(user=user2, group__social_provider=Dojo_Group.SAML)
        
        self.assertEqual(user1_memberships.count(), 2)
        self.assertEqual(user2_memberships.count(), 2)
        
        # Verify the groups are the same objects (not duplicated)
        total_saml_groups = Dojo_Group.objects.filter(social_provider=Dojo_Group.SAML).count()
        self.assertEqual(total_saml_groups, 2)
