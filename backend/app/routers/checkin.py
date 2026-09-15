# Check-in and check-out routes

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.visitor import VisitRecord
from app.routers.auth import get_current_user
from app.schemas.visitor import CheckInRequest, CheckOutRequest, VisitRecordResponse
from app.services.audit import log_action

from app.services.encryption import decrypt_field
from app.services.masking import mask_id_number, mask_phone


router = APIRouter()

#check-in
@router.post("/", response_model=VisitRecordResponse, status_code=201)
async def check_in_visitor(
    checkin_data: CheckInRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Create a new visit record
    visit_record = VisitRecord(
        visitor_id=checkin_data.visitor_id,
        purpose=checkin_data.purpose,
        host_name=checkin_data.host_name,
        host_department=checkin_data.host_department,
        badge_number=checkin_data.badge_number,
        notes=checkin_data.notes,
        checked_in_by=current_user.id,
    )
    db.add(visit_record)
    db.commit()
    db.refresh(visit_record)

    #auditlogging via audit service
    log_action(db, action="checkin", resource_type="visit_record", user_id=current_user.id, resource_id=visit_record.id, details=f"Checked in visitor {checkin_data.visitor_id}")

    return visit_record


#check-out
@router.post("/checkout", response_model=VisitRecordResponse)
async def check_out_visitor(
    checkout_data: CheckOutRequest,
    db: Session=Depends(get_db),
    current_user: User=Depends(get_current_user),
):
    visit_record=(
        db.query(VisitRecord)
        .filter(VisitRecord.id==checkout_data.visit_record_id)
        .first()
    )
    if not visit_record:
        raise HTTPException(status_code=404, detail="visit record not found")
    if visit_record.check_out_time:
        raise HTTPException(status_code=400, detail="visitor already checked out")

    visit_record.check_out_time= datetime.utcnow()
    visit_record.checked_out_by=current_user.id
    if checkout_data.notes:
        visit_record.notes=checkout_data.notes

    db.commit()
    db.refresh(visit_record)

    #auditlogging via audit service
    log_action(db, action="checkout", resource_type="visit_record", user_id=current_user.id, resource_id=visit_record.id, details=f"Checked out visitor {visit_record.visitor_id}")

    return visit_record


#list active visitors with full info
@router.get("/active")
async def get_active_visits(
    db: Session=Depends(get_db),
    current_user: User=Depends(get_current_user),
):
    from app.models.visitor import Visitor

    visits = (
        db.query(VisitRecord)
        .filter(VisitRecord.check_out_time.is_(None))
        .order_by(VisitRecord.check_in_time.desc())
        .all()
    )
    results =[]
    for visit in visits:
        visitor = db.query(Visitor).filter(Visitor.id==visit.visitor_id).first()
        results.append({
            
            "id": visit.id,
            "visitor_id": visit.visitor_id,
            "purpose": visit.purpose,
            "host_name": visit.host_name,
            "host_department": visit.host_department,
            "badge_number": visit.badge_number,
            "check_in_time": visit.check_in_time,
            "check_out_time": visit.check_out_time,
            "notes": visit.notes,
            "visitor_name": visitor.full_name if visitor else "Unknown",
            "visitor_email": visitor.email if visitor else "",
            "visitor_phone": mask_phone(decrypt_field(visitor.phone), current_user.role) if visitor else "",
            "visitor_id_type": visitor.id_type if visitor else None,
            "visitor_id_number": mask_id_number(
                decrypt_field(visitor.id_number), current_user.role
            ) if visitor else None,

        })
    return results
