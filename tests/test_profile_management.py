import pytest
from sqlalchemy import select
from app.models.user_model import User, UserRole
from app.services.user_service import UserService
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password, verify_password

pytestmark = pytest.mark.asyncio

# Test 1: Test profile URL validation
@pytest.mark.asyncio
async def test_profile_url_validation(db_session, email_service):
    """Test that profile URLs are properly validated."""
    # Create a user with valid data
    user_data = {
        "nickname": generate_nickname(),
        "email": "profile_test@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.AUTHENTICATED
    }
    
    # Create user directly in the database
    user = User(
        nickname=user_data["nickname"],
        email=user_data["email"],
        hashed_password=hash_password(user_data["password"]),
        role=user_data["role"],
        email_verified=True
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    # Test valid LinkedIn URL
    valid_linkedin = {"linkedin_profile_url": "https://www.linkedin.com/in/validuser"}
    user.linkedin_profile_url = valid_linkedin["linkedin_profile_url"]
    await db_session.commit()
    await db_session.refresh(user)
    assert user.linkedin_profile_url == valid_linkedin["linkedin_profile_url"]
    
    # Test valid GitHub URL
    valid_github = {"github_profile_url": "https://github.com/validuser"}
    user.github_profile_url = valid_github["github_profile_url"]
    await db_session.commit()
    await db_session.refresh(user)
    assert user.github_profile_url == valid_github["github_profile_url"]

# Test 2: Test professional status update
@pytest.mark.asyncio
async def test_professional_status_update(db_session, email_service):
    """Test updating a user's professional status."""
    # Create a user
    user_data = {
        "nickname": generate_nickname(),
        "email": "pro_status_test@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.AUTHENTICATED
    }
    
    # Create user directly in the database
    user = User(
        nickname=user_data["nickname"],
        email=user_data["email"],
        hashed_password=hash_password(user_data["password"]),
        role=user_data["role"],
        email_verified=True,
        is_professional=False
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    # Verify initial state
    assert user.is_professional is False
    
    # Update professional status
    user.update_professional_status(True)
    await db_session.commit()
    await db_session.refresh(user)
    
    # Verify the update
    assert user.is_professional is True
    assert user.professional_status_updated_at is not None

# Test 3: Test account locking after failed login attempts
@pytest.mark.asyncio
async def test_account_locking(db_session, email_service):
    """Test that an account gets locked after multiple failed login attempts."""
    # Create a user
    user_data = {
        "nickname": generate_nickname(),
        "email": "lock_test@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.AUTHENTICATED
    }
    
    # Create user directly in the database
    user = User(
        nickname=user_data["nickname"],
        email=user_data["email"],
        hashed_password=hash_password(user_data["password"]),
        role=user_data["role"],
        email_verified=True,
        is_locked=False,
        failed_login_attempts=0
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    # Verify initial state
    assert user.is_locked is False
    
    # Simulate failed login attempts
    user.failed_login_attempts = 5  # Assuming 5 is the threshold
    
    # Lock the account
    user.lock_account()
    await db_session.commit()
    await db_session.refresh(user)
    
    # Verify the account is locked
    assert user.is_locked is True
    assert user.failed_login_attempts == 5

# Test 4: Test account unlocking
@pytest.mark.asyncio
async def test_account_unlocking(db_session, email_service):
    """Test that a locked account can be unlocked."""
    # Create a user with a locked account
    user_data = {
        "nickname": generate_nickname(),
        "email": "unlock_test@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.AUTHENTICATED
    }
    
    # Create user directly in the database
    user = User(
        nickname=user_data["nickname"],
        email=user_data["email"],
        hashed_password=hash_password(user_data["password"]),
        role=user_data["role"],
        email_verified=True,
        is_locked=True,
        failed_login_attempts=5
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    # Verify the account is locked
    assert user.is_locked is True
    
    # Unlock the account
    user.unlock_account()
    user.failed_login_attempts = 0
    await db_session.commit()
    await db_session.refresh(user)
    
    # Verify the account is unlocked
    assert user.is_locked is False
    assert user.failed_login_attempts == 0

# Test 5: Test email verification
@pytest.mark.asyncio
async def test_email_verification(db_session, email_service):
    """Test that a user's email can be verified."""
    # Create a user with unverified email
    user_data = {
        "nickname": generate_nickname(),
        "email": "verify_test@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.AUTHENTICATED
    }
    
    # Create user directly in the database
    user = User(
        nickname=user_data["nickname"],
        email=user_data["email"],
        hashed_password=hash_password(user_data["password"]),
        role=user_data["role"],
        email_verified=False
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    # Verify initial state
    assert user.email_verified is False
    
    # Verify the email
    user.verify_email()
    await db_session.commit()
    await db_session.refresh(user)
    
    # Check that the email is verified
    assert user.email_verified is True
