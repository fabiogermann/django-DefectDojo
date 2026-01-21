import logging
import re

from django.conf import settings
from djangosaml2.backends import Saml2Backend as _Saml2Backend
from django.utils.functional import cached_property

from dojo.models import Dojo_Group, Dojo_Group_Member, Role
from dojo.authorization.roles_permissions import Roles
from dojo.pipeline import assign_user_to_groups

logger = logging.getLogger(__name__)


class Saml2Backend(_Saml2Backend):
    """
    Custom SAML2 backend that handles automatic group mapping from SAML assertions.
    
    This backend extends the default djangosaml2 backend to automatically:
    - Create DefectDojo groups based on SAML assertion attributes
    - Add users to those groups with a default role
    - Optionally filter groups using regex
    - Clean up old group memberships
    """

    @cached_property
    def group_re(self):
        """
        Returns a compiled regex pattern for filtering group names.
        
        Returns None if group mapping is disabled (no SAML2_GROUPS_ATTRIBUTE set).
        Returns a regex that matches everything if no filter is configured.
        Returns a compiled regex pattern if SAML2_GROUPS_FILTER is set.
        """
        if settings.SAML2_ENABLED and settings.SAML2_GROUPS_ATTRIBUTE:
            if settings.SAML2_GROUPS_FILTER:
                return re.compile(settings.SAML2_GROUPS_FILTER)
            return re.compile(r".*")  # Match all groups if no filter specified
        return None

    def _update_user(self, user, attributes: dict, attribute_mapping: dict, force_save: bool = False, *args, **kwargs):
        """
        Override parent method to add group processing after user update.
        
        Args:
            user: The Django user object being updated
            attributes: Dictionary of SAML attributes
            attribute_mapping: Mapping of SAML attribute names to user fields
            force_save: Whether to force saving the user
        
        Returns:
            The updated user object
        """
        # First, call the parent implementation to update user attributes
        user = super()._update_user(user, attributes, attribute_mapping, force_save, *args, **kwargs)
        
        # Then process group assignments if group mapping is enabled
        if self.group_re is not None:
            self._process_user_groups(user, attributes)
        
        return user

    def _process_user_groups(self, user, attributes: dict):
        """
        Process SAML group attributes and update user's group memberships.
        
        This method:
        1. Extracts group names from the SAML assertion
        2. Filters them using the configured regex (if any)
        3. Creates groups and assigns the user to them
        4. Removes the user from old SAML groups not in the assertion
        
        Args:
            user: The Django user object
            attributes: Dictionary of SAML attributes from the assertion
        """
        try:
            # Get the group attribute value from SAML assertion
            groups_raw = attributes.get(settings.SAML2_GROUPS_ATTRIBUTE, [])
            
            # Ensure we have a list (some IdPs might send a single string)
            if isinstance(groups_raw, str):
                groups_raw = [groups_raw]
            
            logger.debug(f"Processing SAML groups for user {user.username}: {groups_raw}")
            
            # Filter groups using the regex pattern
            group_names = []
            for group_name in groups_raw:
                if self.group_re.match(group_name):
                    group_names.append(group_name)
                else:
                    logger.debug(f"Skipping group '{group_name}' - doesn't match filter pattern")
            
            logger.info(f"Filtered SAML groups for user {user.username}: {group_names}")
            
            # Assign user to the filtered groups
            if group_names:
                assign_user_to_groups(user, group_names, Dojo_Group.SAML)
            
            # Clean up old group memberships
            # Get all current SAML group memberships for this user
            current_saml_groups = set(
                Dojo_Group.objects.filter(
                    dojo_group_member__user=user,
                    social_provider=Dojo_Group.SAML
                )
            )
            
            # Get the groups the user should be in based on SAML assertion
            target_groups = set(
                Dojo_Group.objects.filter(
                    name__in=group_names,
                    social_provider=Dojo_Group.SAML
                )
            )
            
            # Calculate groups to remove user from
            groups_to_remove = current_saml_groups - target_groups
            
            # Remove user from old SAML groups
            if groups_to_remove:
                removed_count = Dojo_Group_Member.objects.filter(
                    user=user,
                    group__in=groups_to_remove
                ).delete()[0]
                
                logger.info(
                    f"Removed user {user.username} from {removed_count} SAML group(s): "
                    f"{[g.name for g in groups_to_remove]}"
                )
                
                # Log a warning if the deleted count doesn't match expected
                if removed_count != len(groups_to_remove):
                    logger.warning(
                        f"Expected to remove user {user.username} from {len(groups_to_remove)} "
                        f"SAML groups but actually removed from {removed_count}"
                    )
        
        except Exception as e:
            logger.exception(f"Error processing SAML groups for user {user.username}: {e}")
            # Don't fail the authentication if group processing fails
            pass
