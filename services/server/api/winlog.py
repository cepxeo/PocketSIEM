from pydantic import BaseModel
from database.models import db, User, Login, Process, File, Event
from detect import tasks

class WinLog(BaseModel):
    date: str
    host: str
    image: str
    #field_names: dict
    #or_field_names: dict

class SysmonProcessLog(WinLog):
    company: str
    command_line: str
    parent_image: str
    parent_command_line: str
    description: str
    product: str
    original_file_name: str
    process_user: str

    def check_log(self):
        tasks.check_log.delay(self.date, self.host, self.image, self.command_line)
        tasks.check_process.delay(self.date, self.host, self.image, self.command_line, self.parent_image, self.parent_command_line, self.description, self.product, self.original_file_name, self.process_user)
        
    def save_log(self) -> None:
        saveProcess = Process(date=self.date, host=self.host, image=self.image, field4=self.company, field5=self.command_line, \
            parent_image=self.parent_image, parent_command_line=self.parent_command_line, description=self.description, \
            product=self.product, original_file_name=self.original_file_name, process_user=self.process_user)
        db.session.add(saveProcess)
        db.session.commit()
        
class SysmonFileLog(WinLog):
    company: str
    command_line: str
    parent_image: str

# #Test2
# new_process_log = SysmonProcessLog("somedate", "somehost", "someimage", "somecompany", "some command_line", "some parent_image")
# print(new_process_log.image)
# print(new_process_log.command_line)

# Test3
# parsed_fields = {"date":"whatever", "host":"whatever", "image":"whatever", "company":"whatever", "command_line":"whatever", 
#     "parent_image":"whatever", "parent_command_line":"whatever", "description":"whatever", "product":"whatever", "original_file_name":"whatever", "process_user":"whatever"}
# newProcess = SysmonProcessLog.parse_obj(parsed_fields)
# print(newProcess)
# print(newProcess.command_line)
# print(newProcess.host)
# newProcess.check_log()
# newProcess.save_log()