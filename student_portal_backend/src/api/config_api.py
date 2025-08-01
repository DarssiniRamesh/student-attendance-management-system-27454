from fastapi import APIRouter, Depends, HTTPException
from typing import Optional, Dict
from sqlmodel import SQLModel, Field, Session, select
from pydantic import BaseModel
from .main import get_session, get_current_role

# =================== CONFIG MODEL =====================

class SystemConfig(SQLModel, table=True):
    __tablename__ = "system_config"
    key: str = Field(primary_key=True, index=True, description="Configuration parameter key")
    value: str = Field(nullable=False, description="Configuration parameter value")
    description: Optional[str] = Field(default=None, description="Optional description of this parameter")

class SystemConfigRead(BaseModel):
    key: str
    value: str
    description: Optional[str] = None

    class Config:
        from_attributes = True

class SystemConfigUpdate(BaseModel):
    value: str

# =================== API ROUTES =====================

router = APIRouter(
    prefix="",
    tags=["SystemConfig"],
    responses={404: {"description": "Not found"}}
)

# PUBLIC_INTERFACE
@router.get(
    "/system-config",
    response_model=Dict[str, SystemConfigRead],
    summary="Get all system config",
    description="Get all system configuration parameters.",
    status_code=200,
    tags=["SystemConfig"],
)
def get_system_config(
    session: Session = Depends(get_session),
    current_user=Depends(get_current_role("admin")),  # Allow admin/operator roles in get_current_role
):
    """
    Retrieve all system configuration parameters as key-value pairs.
    Requires admin/operator access.
    """
    configs = session.exec(select(SystemConfig)).all()
    result = {c.key: SystemConfigRead.from_orm(c) for c in configs}
    return result

# PUBLIC_INTERFACE
@router.put(
    "/system-config/{key}",
    response_model=SystemConfigRead,
    summary="Update system config parameter",
    description="Update an existing system configuration parameter. Only admins/operators allowed.",
    status_code=200,
    tags=["SystemConfig"],
)
def update_system_config(
    key: str,
    update: SystemConfigUpdate,
    session: Session = Depends(get_session),
    current_user=Depends(get_current_role("admin"))
):
    """
    Update a single system configuration parameter by key.
    Only admin/operator access.
    """
    config: Optional[SystemConfig] = session.get(SystemConfig, key)
    if not config:
        raise HTTPException(status_code=404, detail=f"Config key '{key}' not found.")
    config.value = update.value
    session.add(config)
    session.commit()
    session.refresh(config)
    return SystemConfigRead.from_orm(config)

# PUBLIC_INTERFACE
@router.put(
    "/system-config",
    response_model=Dict[str, SystemConfigRead],
    summary="Bulk update system config parameters",
    description="Bulk update (replace) several config params at once. Only admins/operators allowed.",
    status_code=200,
    tags=["SystemConfig"],
)
def bulk_update_system_config(
    updates: Dict[str, SystemConfigUpdate],
    session: Session = Depends(get_session),
    current_user=Depends(get_current_role("admin"))
):
    """
    Bulk update system configuration parameters. Only admin/operator access.
    Accepts a dictionary where keys are parameter names and values are dicts with the new value.
    """
    keys = list(updates.keys())
    configs = session.exec(select(SystemConfig).where(SystemConfig.key.in_(keys))).all()
    found_keys = {c.key for c in configs}
    resp = {}

    for key, upd in updates.items():
        if key not in found_keys:
            raise HTTPException(status_code=404, detail=f"Config key '{key}' not found.")
    for config in configs:
        config.value = updates[config.key].value
        session.add(config)
        resp[config.key] = SystemConfigRead.from_orm(config)
    session.commit()
    return resp

