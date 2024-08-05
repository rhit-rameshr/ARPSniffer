import sqlite3
from scapy.all import ARP, sniff
import keyboard
import sys

'''
   First, we create a database or invoke one that already exists, then we create a table that has mac_address as a primary key.
   Then we run our ARP sniffer which returns MAC and IP addresses. Then we need to get our MAC and IP addresses to go into the 
   database we created.


'''




class ARPSniffer:
    mac_list = []

    def _init_(self):
        self.ip_list = []

    @classmethod
    def get_mac(cls, packet):
        if packet[ARP].op == 2:
            source_mac = packet[ARP].hwsrc
            source_ip = packet[ARP].psrc
            dst_mac = packet[ARP].hwdst
            dst_ip = packet[ARP].pdst
            AssetInventory.add_to_list(source_mac,source_ip)
            AssetInventory.add_to_list(dst_mac,dst_ip)
            return f"*Response: {packet[ARP].hwsrc} has address {packet[ARP].psrc}"

    @classmethod
    def start(cls):
        sniff(filter="arp", prn=cls.get_mac)

    @classmethod
    def stop(cls):
        if keyboard.is_pressed("ctrl + c"):
            sys.exit()


class SqliteConnect:
    db = sqlite3.connect("addresses6.db")
    cursor = db.cursor()

    def _init(self):
        pass

    @classmethod
    def create(cls):

        table = """ CREATE TABLE ADDRESSES (
                    mac_address VARCHAR(255) PRIMARY KEY,
                    ip_address VARCHAR(255) NOT NULL

               ); """

        cls.cursor.execute(table)
        print("Table is Ready")

    @classmethod
    def add(cls,mac,ip):
        sql = '''INSERT OR IGNORE INTO ADDRESSES(mac_address,ip_address) VALUES (?,?)'''
        data = (mac,ip)
        cls.cursor.execute(sql,data)
        cls.db.commit()


class AssetInventory:

    def _init_(self):
        pass

    @classmethod
    def add_to_list(cls, mac,ip):
        SqliteConnect.add(mac,ip)


if __name__ == "__main__":
    arp_sniffer = ARPSniffer()
    ARPSniffer.start()
    ARPSniffer.stop()
