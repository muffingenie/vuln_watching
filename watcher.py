import requests
import feedparser
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from bs4 import BeautifulSoup

def get_nvd_cves():
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    params = {"pubStartDate": f"{yesterday}T00:00:00.000Z", "pubEndDate": f"{yesterday}T23:59:59.999Z"}
    
    response = requests.get(base_url, params=params)
    if response.status_code == 200:
        cve_data = response.json().get("vulnerabilities", [])
        cves = []
        for item in cve_data:
            cve_id = item.get("cve", {}).get("id", "N/A")
            descriptions = item.get("cve", {}).get("descriptions", [])
            description = descriptions[0].get("value", "No description") if descriptions else "No description"
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id != "N/A" else "#"
            
            cvss_metrics = item.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [])
            cvss_score = "N/A"
            if cvss_metrics:
                cvss_score = cvss_metrics[0].get("cvssData", {}).get("baseScore", "N/A")
            
            cves.append({"id": cve_id, "description": description, "cvss": cvss_score, "link": link})
        return cves
    return []

def get_mitre_cves():
    url = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/releases/latest.json"
    response = requests.get(url)
    
    if response.status_code != 200:
        return []
    
    data = response.json()
    today = datetime.utcnow().strftime("%Y-%m-%d")
    
    cves = [
        {
            "id": entry.get("cveID", "N/A"),
            "description": entry.get("containers", {}).get("cna", {}).get("descriptions", [{}])[0].get("value", "No description"),
            "link": f"https://www.cve.org/CVERecord?id={entry.get('cveID', 'N/A')}"
        }
        for entry in data.get("CVE_Items", [])
        if entry.get("dateUpdated", "").startswith(today)
    ]
    
    return cves

def get_cisa_known_exploited_vulnerabilities():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url)
    
    if response.status_code != 200:
        return []
    
    data = response.json()
    today = datetime.utcnow().strftime("%Y-%m-%d")
    
    vulnerabilities = [
        {
            "cve": item.get("cveID", "N/A"),
            "vendor": item.get("vendorProject", "N/A"),
            "product": item.get("product", "N/A"),
            "description": item.get("shortDescription", "No description"),
            "date_added": item.get("dateAdded", "N/A"),
            "link": f"https://www.cve.org/CVERecord?id={item.get('cveID', 'N/A')}"
        }
        for item in data.get("vulnerabilities", [])
        if item.get("dateAdded", "").startswith(today)
    ]
    
    return vulnerabilities

def send_email(subject, body, recipient):
    sender_email = "send@mail.com"  # CHANGE ME
    sender_password = "password"  # CHANGE ME
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient, msg.as_string())
        server.quit()
        print("Email send")
    except Exception as e:
        print(f"Cannot send the email: {e}")


def format_email_content(nvd, mitre, cisa):
    def format_section(title, items):
        if not items:
            return f"{title}: No news today.\n\n"
        return f"{title}:\n" + "\n".join([f"- {item.get('id', 'N/A')} - {item.get('description', 'No description')} (CVSS: {item.get('cvss', 'N/A')}) ({item.get('link', '#')})" for item in items]) + "\n\n"
    
    content = """
    Daily Cybersecurity Threat Report
    ==================================
    
    """
    content += format_section("NVD CVEs", nvd)
    content += format_section("MITRE CVEs", mitre)
    content += format_section("CISA Exploited CVEs", cisa)
    

def main():
    nvd_cves = get_nvd_cves()
    mitre_cves = get_mitre_cves()
    cisa_cves = get_cisa_known_exploited_vulnerabilities()
    
    email_content = format_email_content(nvd_cves, mitre_cves, cisa_cves)
    send_email("Daily Cybersecurity Report", email_content, "CHANGE_ME") #recepient email
    
if __name__ == "__main__":
    main()
