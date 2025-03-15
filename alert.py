import smtplib
import sqlite3

class Alert:
    def __init__(self, time, src_ip, dst_ip, message, attack):
        self.time = time
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.message = message
        self.attack = attack
    
    def add_to_alert_table(self, conn):
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO alerts 
            (
                timestamp,  
                src_ip,
                dst_ip,
                message,
                attack
            )
            VALUES (?, ?, ?, ?, ?)  
            """,
            (
                self.time,  
                self.src_ip, 
                self.dst_ip, 
                self.message,
                self.attack
            )
        )
        conn.commit()
        

    @classmethod
    def get_alerts_from_db(cls, conn):
        cursor = conn.cursor()
        query = "SELECT * FROM alerts"
        
        cursor.execute(query)
        rows = cursor.fetchall()
        
        alerts = []
        
        for row in rows:
            alert = cls(
                time = row[1],  
                src_ip = row[2],
                dst_ip = row[3],
                message = row[4],
                attack = row[5]
            )
            
            alerts.append(alert)

        return alerts
