from builtins import str
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from uuid import UUID

from app.dependencies import get_current_user, get_db, get_email_service
from app.models.user_model import User, UserRole
from app.schemas.user_schemas import UserUpdate
from app.services.user_service import UserService
from app.services.email_service import EmailService

router = APIRouter(
    prefix="/profiles",
    tags=["profiles"],
    responses={404: {"description": "Not found"}},
)

@router.get("/{user_id}", response_model=dict)
async def get_user_profile(
    user_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get a user's profile information.
    
    Regular users can only view their own profile.
    Managers and admins can view any profile.
    """
    # Check permissions
    if (current_user.id != user_id and 
        current_user.role != UserRole.ADMIN and 
        current_user.role != UserRole.MANAGER):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this profile"
        )
    
    # Get the user
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Return profile information
    return {
        "id": str(user.id),
        "nickname": user.nickname,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "bio": user.bio,
        "profile_picture_url": user.profile_picture_url,
        "linkedin_profile_url": user.linkedin_profile_url,
        "github_profile_url": user.github_profile_url,
        "is_professional": user.is_professional,
        "professional_status_requested": user.professional_status_requested,
        "role": user.role.name
    }

@router.put("/{user_id}", response_model=dict)
async def update_profile(
    user_id: UUID,
    profile_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Update a user's profile information.
    
    Regular users can only update their own profile.
    Managers and admins can update any profile.
    """
    # Check permissions
    if (current_user.id != user_id and 
        current_user.role != UserRole.ADMIN and 
        current_user.role != UserRole.MANAGER):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this profile"
        )
    
    # Prevent role changes by regular users
    if profile_data.role is not None and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to change user roles"
        )
    
    # Prevent professional status changes directly
    if profile_data.is_professional is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Professional status cannot be changed directly. Use the request/approve endpoints."
        )
    
    # Update the profile
    updated_user = await UserService.update(db, user_id, profile_data.model_dump(exclude_unset=True))
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found or update failed"
        )
    
    # Return updated profile
    return {
        "id": str(updated_user.id),
        "nickname": updated_user.nickname,
        "email": updated_user.email,
        "first_name": updated_user.first_name,
        "last_name": updated_user.last_name,
        "bio": updated_user.bio,
        "profile_picture_url": updated_user.profile_picture_url,
        "linkedin_profile_url": updated_user.linkedin_profile_url,
        "github_profile_url": updated_user.github_profile_url,
        "is_professional": updated_user.is_professional,
        "professional_status_requested": updated_user.professional_status_requested,
        "role": updated_user.role.name
    }

@router.post("/{user_id}/request-professional", response_model=dict)
async def request_professional_status(
    user_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Request professional status for a user.
    
    Users can only request professional status for themselves.
    The user must have a complete profile to be eligible.
    """
    # Check permissions
    if current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to request professional status for another user"
        )
    
    # Check if already professional
    if current_user.is_professional:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has professional status"
        )
    
    # Check if already requested
    if current_user.professional_status_requested:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Professional status already requested"
        )
    
    # Request professional status
    updated_user = await UserService.request_professional_status(db, user_id)
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Professional status request failed. Please complete your profile."
        )
    
    return {
        "id": str(updated_user.id),
        "nickname": updated_user.nickname,
        "professional_status_requested": updated_user.professional_status_requested,
        "message": "Professional status requested successfully. Your request will be reviewed."
    }

@router.post("/{user_id}/approve-professional", response_model=dict)
async def approve_professional_status(
    user_id: UUID,
    approve: bool,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service),
):
    """
    Approve or reject a professional status request.
    
    Only managers and admins can approve professional status requests.
    """
    # Check permissions
    if current_user.role != UserRole.ADMIN and current_user.role != UserRole.MANAGER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to approve professional status requests"
        )
    
    # Get the user
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check if request exists
    if not user.professional_status_requested:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No professional status request found for this user"
        )
    
    # Approve or reject
    updated_user = await UserService.approve_professional_status(db, user_id, approve, email_service)
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to update professional status"
        )
    
    status_message = "approved" if approve else "rejected"
    return {
        "id": str(updated_user.id),
        "nickname": updated_user.nickname,
        "is_professional": updated_user.is_professional,
        "message": f"Professional status request {status_message} successfully."
    }

@router.get("/requests", response_model=List[dict])
async def get_professional_status_requests(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get all pending professional status requests.
    
    Only managers and admins can view professional status requests.
    """
    # Check permissions
    if current_user.role != UserRole.ADMIN and current_user.role != UserRole.MANAGER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view professional status requests"
        )
    
    # Get all users with pending requests
    users = await UserService.list_users(db)
    pending_requests = [
        {
            "id": str(user.id),
            "nickname": user.nickname,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "requested_at": user.professional_status_updated_at
        }
        for user in users if user.professional_status_requested
    ]
    
    return pending_requests
