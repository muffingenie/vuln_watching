
import requests
import json
import smtplib
import feedparser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone

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
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    
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
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    
    vulnerabilities = [
        {
            "id": item.get("cveID", "N/A"),
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


def get_bleeping_computer_articles():
    feed_url = "https://www.bleepingcomputer.com/feed/"
    feed = feedparser.parse(feed_url)
    
    articles = [
        {
            "title": entry.get("title", "No title"),
            "description": entry.get("summary", ""),
            "link": entry.get("link", "#")
        }
        for entry in feed.entries if "vulnerability" in entry.get("title", "").lower() or "vulnerability" in entry.get("summary", "").lower()
    ]
    
    return articles

def format_email_content(nvd, mitre, cisa, articles):
    email_content = """
    <html>
    <body>
        <h2>Daily Cybersecurity Threat Report</h2>
        <hr>
        <h3>NVD CVEs</h3>
        <ul>
    """
    for cve in nvd:
        email_content += f"<li><b>{cve['id']}</b> - {cve['description']} (CVSS: <b>{cve['cvss']}</b>) - <a href='{cve['link']}'>Details</a></li>"
    
    email_content += "</ul><h3>MITRE CVEs</h3><ul>"
    for cve in mitre:
        email_content += f"<li><b>{cve['id']}</b> - {cve['description']} - <a href='{cve['link']}'>Details</a></li>"
    
    email_content += "</ul><h3>CISA Exploited CVEs</h3><ul>"
    for vuln in cisa:
        email_content += f"<li><b>{vuln['id']}</b> - {vuln['description']} - <a href='{vuln['link']}'>Details</a></li>"
    
    email_content += "</ul><h3>Bleeping Computer Articles</h3><ul>"
    for article in articles:
        email_content += f"<li><a href='{article['link']}'><b>{article['title']}</b></a><br>{article['description']}</li>"
    
    email_content += """
        </ul>
    </body>
    </html>
    """
    return email_content


def send_email(subject, body, recipient):
    sender_email = "CHANGE_ME" #add your email account
    sender_password = "CHANGE_ME"  # add your email account password
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))
    
    try:
        server = smtplib.SMTP_SSL("CHANGE_ME", 465)  # add SMTP configuration
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient, msg.as_string())
        server.quit()
        print("Email envoyé avec succès!")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email: {e}")

def main():
    nvd_cves = get_nvd_cves()
    mitre_cves = get_mitre_cves()
    cisa_cves = get_cisa_known_exploited_vulnerabilities()
    articles = get_bleeping_computer_articles()
    
    email_content = format_email_content(nvd_cves, mitre_cves, cisa_cves, articles)
    send_email("Daily Cybersecurity Report", email_content, "CHANGE_ME") #add recipient email
    
if __name__ == "__main__":
    main()







