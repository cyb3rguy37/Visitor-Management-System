#Visitor management routes, CRUD and search operations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.visitor import Visitor, VisitRecord
from app.schemas.visitor import VisitorCreate, VisitorResponse
from app.services.audit import log_action
from app.routers.auth import get_current_user, require_role

from app.services.encryption import encrypt_field, decrypt_field, blind_index
from app.services import id_verification
from app.services.masking import mask_id_number, mask_phone


router = APIRouter()

#listing visitors + search capability
@router.get("/", response_model=list[VisitorResponse])
async def list_visitors(
    search: Optional[str] = Query(None, description="Search by name, email or phone"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Visitor)

    if search:
        search_filter = f"%{search}%"
        search_bidx = blind_index(search)
        query = query.filter(
            Visitor.full_name.ilike(search_filter)
            | Visitor.email.ilike(search_filter)
            | (Visitor.phone_bidx == search_bidx)
            | (Visitor.id_number_bidx == search_bidx)
        )

    visitors = query.offset(skip).limit(limit).all()

    #build responses with decrypted + masked values
    results = []
    for v in visitors:
        results.append(VisitorResponse(
            id=v.id,
            full_name=v.full_name,
            email=v.email,
            phone=mask_phone(decrypt_field(v.phone), current_user.role) if v.phone else v.phone,
            company=v.company,
            id_type=v.id_type,
            id_number=mask_id_number(decrypt_field(v.id_number), current_user.role) if v.id_number else v.id_number,
            verification_status=v.verification_status,
            verification_checked_at=v.verification_checked_at,
            created_at=v.created_at,
        ))
    return results

#creatin a visitor
@router.post("/", response_model=VisitorResponse, status_code=201)
async def create_visitor(
    visitor_data: VisitorCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    visitor = Visitor(**visitor_data.model_dump())

    #run id verification while we still have the plaintext id number, this never blocks registration
    verification = id_verification.verify_id(
        id_type=visitor.id_type,
        id_number=visitor.id_number,
        full_name=visitor.full_name,
    )
    visitor.verification_status = verification["status"]
    visitor.verification_checked_at = datetime.utcnow()

    #encrypt before saving
    if visitor.phone:
        visitor.phone_bidx = blind_index(visitor.phone)
        visitor.phone = encrypt_field(visitor.phone)
    if visitor.id_number:
        visitor.id_number_bidx = blind_index(visitor.id_number)
        visitor.id_number = encrypt_field(visitor.id_number)

    db.add(visitor)
    db.commit()
    db.refresh(visitor)

    #audit while the object still holds ciphertext
    log_action(db, action="create", resource_type="visitor", user_id=current_user.id, resource_id=visitor.id, details=f"Registered visitor {visitor.full_name} (id verification: {visitor.verification_status})")

    #build the response with decrypted + masked values
    return VisitorResponse(
        id=visitor.id,
        full_name=visitor.full_name,
        email=visitor.email,
        phone=mask_phone(decrypt_field(visitor.phone), current_user.role) if visitor.phone else visitor.phone,
        company=visitor.company,
        id_type=visitor.id_type,
        id_number=mask_id_number(decrypt_field(visitor.id_number), current_user.role) if visitor.id_number else visitor.id_number,
        verification_status=visitor.verification_status,
        verification_checked_at=visitor.verification_checked_at,
        created_at=visitor.created_at,
    )


#Read one visitor by ID
@router.get("/{visitor_id}", response_model=VisitorResponse)
async def get_visitor(
    visitor_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    visitor = db.query(Visitor).filter(Visitor.id == visitor_id).first()
    
    if not visitor:
        raise HTTPException(status_code=404, detail="Visitor not found")

    return VisitorResponse(
        id=visitor.id,
        full_name=visitor.full_name,
        email=visitor.email,
        phone=mask_phone(decrypt_field(visitor.phone), current_user.role) if visitor.phone else visitor.phone,
        company=visitor.company,
        id_type=visitor.id_type,
        id_number=mask_id_number(decrypt_field(visitor.id_number), current_user.role) if visitor.id_number else visitor.id_number,
        verification_status=visitor.verification_status,
        verification_checked_at=visitor.verification_checked_at,
        created_at=visitor.created_at,
    )


#Updating visitor record
@router.put("/{visitor_id}", response_model=VisitorResponse)
async def update_visitor(
    visitor_id: int,
    visitor_data: VisitorCreate,
    db: Session= Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    
    visitor = db.query(Visitor).filter(Visitor.id == visitor_id).first()

    if not visitor:
        raise HTTPException(status_code=404, detail="Visitor not found")

    for key, value in visitor_data.model_dump().items():
        setattr(visitor, key, value)

    if visitor.phone:
        visitor.phone_bidx = blind_index(visitor.phone)
        visitor.phone = encrypt_field(visitor.phone)
    if visitor.id_number:
        visitor.id_number_bidx = blind_index(visitor.id_number)
        visitor.id_number = encrypt_field(visitor.id_number)

    db.commit()
    db.refresh(visitor)

    return VisitorResponse(
        id=visitor.id,
        full_name=visitor.full_name,
        email=visitor.email,
        phone=mask_phone(decrypt_field(visitor.phone), current_user.role) if visitor.phone else visitor.phone,
        company=visitor.company,
        id_type=visitor.id_type,
        id_number=mask_id_number(decrypt_field(visitor.id_number), current_user.role) if visitor.id_number else visitor.id_number,
        verification_status=visitor.verification_status,
        verification_checked_at=visitor.verification_checked_at,
        created_at=visitor.created_at,
    )

#Delete visitor (require admin role)
@router.delete("/{visitor_id}", status_code=204)
async def delete_visitor(
    visitor_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),

):

    visitor = db.query(Visitor).filter(Visitor.id == visitor_id).first()

    if not visitor:
        raise HTTPException(status_code=404, detail="Visitor not found")

    visitor_name=visitor.full_name

    #remove all visit records for the visitor first
    db.query(VisitRecord).filter(VisitRecord.visitor_id == visitor_id).delete()
    db.delete(visitor)
    db.commit()

    #audit logging
    log_action(db, action="delete", resource_type="visitor", user_id=current_user.id, resource_id=visitor_id, details=f"Deleted visitor {visitor_name} and all visit records")

    return None


