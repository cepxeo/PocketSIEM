from pydantic import BaseModel
from database.models import db, Login, Process, File, Event, ConnLog
from detect import tasks
import re
from datetime import datetime


def _event_datetime(raw_date):
    epoch_match = re.search(r"\((\d+)", str(raw_date))
    if not epoch_match:
        raise ValueError(f"Unsupported Windows log date format: {raw_date}")
    epoch_time = epoch_match.group(1)[:10]
    return datetime.fromtimestamp(int(epoch_time))


def _save_conn_log(date, host, log_type):
    conn_logs_save = ConnLog(date=date, host=host, log_type=log_type)
    db.session.add(conn_logs_save)
    db.session.commit()


class WinLog(BaseModel):
    logins: list
    processes: list
    nets: list
    files: list
    events: list

    def save_log(self) -> None:
        if self.logins:
            for login in self.logins:
                converted_time = _event_datetime(login["date"])
                date = converted_time
                host = login["host"]
                save_login = Login(date=converted_time, host=login["host"], image=login["osuser"], field4=login["logon_type"], field5=login["process_name"])
                db.session.add(save_login)
                db.session.commit()
            _save_conn_log(date, host, "Login")

        if self.processes:
            for process in self.processes:
                converted_time = _event_datetime(process["date"])

                date=converted_time
                host=process["host"]
                image=process["image"]
                command_line=process["command_line"]
                parent_image=process["parent_image"]
                parent_command_line=process["parent_command_line"]
                original_file_name=process["original_file_name"]
                process_user=process["process_user"]
                company=process["company"]

                if "domain" in command_line or "whoami" in command_line:
                    print (command_line)

                tasks.check_log.delay(date, host, image, command_line)
                tasks.check_process.delay(date, host, image, command_line, parent_image, 
                    parent_command_line, original_file_name, process_user)
                
                process_save = Process(date=date, host=host, image=image, field4=company, field5=command_line, 
                    parent_image=parent_image, parent_command_line=parent_command_line, 
                    original_file_name=original_file_name, process_user=process_user)
                db.session.add(process_save)
                db.session.commit()
            _save_conn_log(date, host, "Process")

        if self.nets:
            for net in self.nets:
                converted_time = _event_datetime(net["date"])

                date=converted_time
                host=net["host"]
                image=net["image"]
                dest_ip=net["dest_ip"]
                dest_port=net["dest_port"]

                tasks.check_network.delay(date, host, image, dest_ip, dest_port)
                # tasks.check_whois.delay(date, host, image, dest_ip, dest_port)
            _save_conn_log(date, host, "Net")

        if self.files:
            for file in self.files:
                converted_time = _event_datetime(file["date"])

                date=converted_time
                host=file["host"]
                image=file["image"]
                filename=file["filename"]
                osuser=file["osuser"]

                tasks.check_log.delay(date, host, image, filename)
                tasks.check_files.delay(date, host, image, filename, osuser)

                file_save = File(date=date, host=host, image=image, field4=filename, field5=osuser)
                db.session.add(file_save)
                db.session.commit()
            _save_conn_log(date, host, "File")

        if self.events:
            for event in self.events:
                converted_time = _event_datetime(event["date"])

                date=converted_time
                host=event["host"]
                image=event["image"]
                event_value=event["event"]
                details=event["details"]

                tasks.check_log.delay(date, host, image, details)
                tasks.check_registry.delay(date, host, image, details)

                event_save = Event(date=date, host=host, image=image, field4=event_value, field5=details)
                db.session.add(event_save)
                db.session.commit()
            _save_conn_log(date, host, "Event")

class SSHLoginLog(BaseModel):
    date: list
    host: list
    osuser: list
    logon_type: list
    process_name: list
    def save_log(self) -> None:
        login = Login(date=self.date[0], host=self.host[0], image=self.osuser[0], field4=self.logon_type[0], field5=self.process_name[0])
        db.session.add(login)
        db.session.commit()
        conn_logs_save = ConnLog(date=self.date[0], host=self.host[0], log_type="SSH Login")
        db.session.add(conn_logs_save)
        db.session.commit()
