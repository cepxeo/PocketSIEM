from pydantic import BaseModel
from database.models import db, Login, Process, File, Event
from detect.tasks import tasks

class WinLog(BaseModel):
    date: str
    host: str

class SysmonLog(WinLog):
    image: str

class WinLoginLog(WinLog):
    osuser: str
    logon_type: str
    process_name: str

    def save_log(self) -> None:
        login = Login(date=self.date, host=self.host, image=self.osuser, field4=self.logon_type, field5=self.process_name)
        db.session.add(login)
        db.session.commit()

class SysmonProcessLog(SysmonLog):
    company: str
    command_line: str
    parent_image: str
    parent_command_line: str
    description: str
    product: str
    original_file_name: str
    process_user: str

    def check_log(self) -> None:
        tasks.check_log.delay(self.date, self.host, self.image, self.command_line)
        #tasks.check_process.delay(self.date, self.host, self.image, self.command_line, self.parent_image, 
        #    self.parent_command_line, self.description, self.product, self.original_file_name, self.process_user)
        tasks.check_process.delay(self)
        
    def save_log(self) -> None:
        process = Process(date=self.date, host=self.host, image=self.image, field4=self.company, field5=self.command_line,
            parent_image=self.parent_image, parent_command_line=self.parent_command_line, description=self.description,
            product=self.product, original_file_name=self.original_file_name, process_user=self.process_user)
        db.session.add(process)
        db.session.commit()
        
class SysmonFileLog(SysmonLog):
    filename: str
    osuser: str

    def check_log(self) -> None:
        tasks.check_log.delay(self.date, self.host, self.image, self.filename)
        tasks.check_files.delay(self.date, self.host, self.image, self.filename, self.osuser)

    def save_log(self) -> None:
        file = File(date=self.date, host=self.host, image=self.image, field4=self.filename, field5=self.osuser)
        db.session.add(file)
        db.session.commit()

class SysmonNetLog(SysmonLog):
    dest_ip: str
    dest_port: str

    def check_log(self) -> None:
        tasks.check_network.delay(self.date, self.host, self.image, self.dest_ip, self.dest_port)
        tasks.check_whois.delay(self.date, self.host, self.image, self.dest_ip, self.dest_port)

class SysmonEventLog(SysmonLog):
    event: str
    details: str

    def check_log(self) -> None:
        tasks.check_log.delay(self.date, self.host, self.image, self.details)
        tasks.check_registry.delay(self.date, self.host, self.image, self.details)

    def save_log(self) -> None:
        event = Event(date=self.date, host=self.host, image=self.image, field4=self.event, field5=self.details)
        db.session.add(event)
        db.session.commit()