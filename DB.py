import sqlite3
import threading

class Database:
    def __init__(self, db_name):
        self.db_name = db_name
        self.conn = None

    
    def connect(self):
        
        try:
            self.conn = sqlite3.connect(self.db_name, check_same_thread=False, timeout=10)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute('PRAGMA journal_mode=WAL;') 
            return self.conn
        
        except sqlite3.Error as e:
            print(f"[Error] Failed to connect to the database: {e}")
            return None

    def create_table_rules(self):
        
        create_table_rules = """
        CREATE TABLE IF NOT EXISTS rules 
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            protocol TEXT,
            src_ip TEXT,
            src_port TEXT,
            direction TEXT,
            dst_ip TEXT,
            dst_port TEXT,
            options TEXT
        );
        """
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(create_table_rules)
            self.conn.commit()
            print("[Success] 'rules' table created or already exists.")
        
        except sqlite3.Error as e:
            print(f"[Database Error] {e}")

    def create_table_logs(self):
        
        create_table_logs = """
        CREATE TABLE IF NOT EXISTS logs 
        (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME,
            event_type TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            message TEXT,
            attack TEXT
        );
        """
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(create_table_logs)
            self.conn.commit()
            print("[Success] 'logs' table created or already exists.")
    
        except sqlite3.Error as e:
            print(f"[Database Error] {e}")

    def create_table_alerts(self):
        
        create_table_alerts = """
        CREATE TABLE IF NOT EXISTS alerts 
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            src_ip TEXT,
            dst_ip TEXT,
            message TEXT,
            attack TEXT
        );
        """
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(create_table_alerts)
            self.conn.commit()
            print("[Success] 'alerts' table created or already exists.")
        
        except sqlite3.Error as e:
            print(f"[Database Error] {e}")

    def clear_table(self, table_name):
        
        try:
            if not self.conn:
                print("[Error] No database connection.")
                return False

            cursor = self.conn.cursor()
            cursor.execute(f"DELETE FROM {table_name};")
            self.conn.commit()
            print(f"[Success] All records from '{table_name}' have been deleted.")
            return True
        
        except sqlite3.Error as e:
            print(f"[Database Error] {e}")
            return False


if __name__ == "__main__":
    
    db_name = "DB/IDS.db"
    db = Database(db_name)

    conn = db.connect()

    if conn:
    
        db.create_table_rules()
        db.create_table_logs()
        db.create_table_alerts()

        db.clear_table("alerts")
        
        conn.close()