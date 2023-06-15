from pydantic import BaseModel
from database.models import db, Alert
from detect import tasks
import re
from datetime import datetime

class FalcoLog(BaseModel):
    time: str
    hostname: str
    output: str
    rule: str
    priority: str
    def save_log(self) -> None:
        newAlert = Alert(date=time, host=hostname, image=priority, field4=rule, field5=output)
        db.session.add(newAlert)
        db.session.commit()