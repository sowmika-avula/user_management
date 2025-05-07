from builtins import Exception, bool, classmethod, int, str
from datetime import datetime, timezone
import secrets
from typing import Optional, Dict, List
from pydantic import ValidationError
from sqlalchemy import func, null, update, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from app.dependencies import get_email_service, get_settings
from app.models.user_model import User
from app.schemas.user_schemas import UserCreate, UserUpdate
from app.utils.nickname_gen import generate_nickname
from app.utils.security import generate_verification_token, hash_password, verify_password
from uuid import UUID
from app.services.email_service import EmailService
from app.models.user_model import UserRole
import logging

settings = get_settings()
logger = logging.getLogger(__name__)

class UserService:
    @classmethod
    async def _execute_query(cls, session: AsyncSession, query):
        try:
            result = await session.execute(query)
            await session.commit()
            return result
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            await session.rollback()
            return None

    @classmethod
    async def _fetch_user(cls, session: AsyncSession, **filters) -> Optional[User]:
        query = select(User).filter_by(**filters)
        result = await cls._execute_query(session, query)
        return result.scalars().first() if result else None

    @classmethod
    async def get_by_id(cls, session: AsyncSession, user_id: UUID) -> Optional[User]:
        return await cls._fetch_user(session, id=user_id)

    @classmethod
    async def get_by_nickname(cls, session: AsyncSession, nickname: str) -> Optional[User]:
        return await cls._fetch_user(session, nickname=nickname)

    @classmethod
    async def get_by_email(cls, session: AsyncSession, email: str) -> Optional[User]:
        return await cls._fetch_user(session, email=email)

    @classmethod
    async def create(cls, session: AsyncSession, user_data: Dict[str, str], email_service: EmailService) -> Optional[User]:
        try:
            validated_data = UserCreate(**user_data).model_dump()
            existing_user = await cls.get_by_email(session, validated_data['email'])
            if existing_user:
                logger.error("User with given email already exists.")
                return None
            validated_data['hashed_password'] = hash_password(validated_data.pop('password'))
            new_user = User(**validated_data)
            new_nickname = generate_nickname()
            while await cls.get_by_nickname(session, new_nickname):
                new_nickname = generate_nickname()
            new_user.nickname = new_nickname
            logger.info(f"User Role: {new_user.role}")
            user_count = await cls.count(session)
            new_user.role = UserRole.ADMIN if user_count == 0 else UserRole.ANONYMOUS            
            if new_user.role == UserRole.ADMIN:
                new_user.email_verified = True

            else:
                new_user.verification_token = generate_verification_token()
                await email_service.send_verification_email(new_user)

            session.add(new_user)
            await session.commit()
            return new_user
        except ValidationError as e:
            logger.error(f"Validation error during user creation: {e}")
            return None

    @classmethod
    async def update(cls, session: AsyncSession, user_id: UUID, update_data: Dict[str, str]) -> Optional[User]:
        try:
            # validated_data = UserUpdate(**update_data).dict(exclude_unset=True)
            validated_data = UserUpdate(**update_data).model_dump(exclude_unset=True)

            if 'password' in validated_data:
                validated_data['hashed_password'] = hash_password(validated_data.pop('password'))
            query = update(User).where(User.id == user_id).values(**validated_data).execution_options(synchronize_session="fetch")
            await cls._execute_query(session, query)
            updated_user = await cls.get_by_id(session, user_id)
            if updated_user:
                session.refresh(updated_user)  # Explicitly refresh the updated user object
                logger.info(f"User {user_id} updated successfully.")
                return updated_user
            else:
                logger.error(f"User {user_id} not found after update attempt.")
            return None
        except Exception as e:  # Broad exception handling for debugging
            logger.error(f"Error during user update: {e}")
            return None

    @classmethod
    async def delete(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if not user:
            logger.info(f"User with ID {user_id} not found.")
            return False
        await session.delete(user)
        await session.commit()
        return True

    @classmethod
    async def list_users(cls, session: AsyncSession, skip: int = 0, limit: int = 10) -> List[User]:
        query = select(User).offset(skip).limit(limit)
        result = await cls._execute_query(session, query)
        return result.scalars().all() if result else []

    @classmethod
    async def register_user(cls, session: AsyncSession, user_data: Dict[str, str], get_email_service) -> Optional[User]:
        return await cls.create(session, user_data, get_email_service)
    

    @classmethod
    async def login_user(cls, session: AsyncSession, email: str, password: str) -> Optional[User]:
        user = await cls.get_by_email(session, email)
        if user:
            if user.email_verified is False:
                return None
            if user.is_locked:
                return None
            if verify_password(password, user.hashed_password):
                user.failed_login_attempts = 0
                user.last_login_at = datetime.now(timezone.utc)
                session.add(user)
                await session.commit()
                return user
            else:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= settings.max_login_attempts:
                    user.is_locked = True
                session.add(user)
                await session.commit()
        return None

    @classmethod
    async def is_account_locked(cls, session: AsyncSession, email: str) -> bool:
        user = await cls.get_by_email(session, email)
        return user.is_locked if user else False
        
    @classmethod
    async def request_professional_status(cls, session: AsyncSession, user_id: UUID) -> Optional[User]:
        """Request professional status upgrade for a user.
        
        This method marks a user as requesting professional status. The user must have
        a complete profile (first name, last name, bio, and at least one profile URL)
        to be eligible for professional status.
        
        Args:
            session: Database session
            user_id: ID of the user requesting professional status
            
        Returns:
            Updated user object if successful, None otherwise
        """
        user = await cls.get_by_id(session, user_id)
        if not user:
            logger.error(f"User with ID {user_id} not found.")
            return None
            
        # Check if profile is complete
        if not cls._is_profile_complete(user):
            logger.error(f"User {user_id} has incomplete profile for professional status.")
            return None
            
        # Set professional status to False but mark as requested in the update data
        update_data = {"professional_status_requested": True}
        return await cls.update(session, user_id, update_data)
    
    @classmethod
    def _is_profile_complete(cls, user: User) -> bool:
        """Check if a user's profile is complete enough for professional status.
        
        A complete profile must have:
        - First name
        - Last name
        - Bio
        - At least one profile URL (LinkedIn, GitHub, or profile picture)
        
        Args:
            user: User object to check
            
        Returns:
            True if profile is complete, False otherwise
        """
        # Check required fields
        if not user.first_name or not user.last_name or not user.bio:
            return False
            
        # Check if at least one profile URL is present
        has_profile_url = any([
            user.linkedin_profile_url,
            user.github_profile_url,
            user.profile_picture_url
        ])
        
        return has_profile_url
    
    @classmethod
    async def approve_professional_status(cls, session: AsyncSession, user_id: UUID, 
                                         approved: bool, email_service: EmailService) -> Optional[User]:
        """Approve or reject a professional status request.
        
        This method can only be called by admin or manager users to approve or reject
        a professional status request.
        
        Args:
            session: Database session
            user_id: ID of the user whose professional status is being updated
            approved: True to approve, False to reject
            email_service: Email service for sending notifications
            
        Returns:
            Updated user object if successful, None otherwise
        """
        user = await cls.get_by_id(session, user_id)
        if not user:
            logger.error(f"User with ID {user_id} not found.")
            return None
            
        # Update professional status
        user.update_professional_status(approved)
        
        # Clear the request flag
        user.professional_status_requested = False
        
        # Save changes
        session.add(user)
        await session.commit()
        
        # Send notification email
        try:
            if approved:
                await email_service.send_professional_status_approved_email(user)
            else:
                await email_service.send_professional_status_rejected_email(user)
        except Exception as e:
            logger.error(f"Failed to send professional status notification email: {e}")
        
        return user


    @classmethod
    async def reset_password(cls, session: AsyncSession, user_id: UUID, new_password: str) -> bool:
        hashed_password = hash_password(new_password)
        user = await cls.get_by_id(session, user_id)
        if user:
            user.hashed_password = hashed_password
            user.failed_login_attempts = 0  # Resetting failed login attempts
            user.is_locked = False  # Unlocking the user account, if locked
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def verify_email_with_token(cls, session: AsyncSession, user_id: UUID, token: str) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.verification_token == token:
            user.email_verified = True
            user.verification_token = None  # Clear the token once used
            user.role = UserRole.AUTHENTICATED
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def count(cls, session: AsyncSession) -> int:
        """
        Count the number of users in the database.

        :param session: The AsyncSession instance for database access.
        :return: The count of users.
        """
        query = select(func.count()).select_from(User)
        result = await session.execute(query)
        count = result.scalar()
        return count
    
    @classmethod
    async def unlock_user_account(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.is_locked:
            user.is_locked = False
            user.failed_login_attempts = 0  # Optionally reset failed login attempts
            session.add(user)
            await session.commit()
            return True
        return False
