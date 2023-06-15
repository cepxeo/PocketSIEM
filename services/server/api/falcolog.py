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
        newAlert = Alert(date=self.time, host=self.hostname, image=self.priority, field4=self.rule, field5=self.output)
        db.session.add(newAlert)
        db.session.commit()