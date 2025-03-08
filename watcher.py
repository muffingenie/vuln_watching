import requests
import feedparser
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
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

def get_bleeping_computer_articles():
    feed_url = "https://www.bleepingcomputer.com/feed/"
    feed = feedparser.parse(feed_url)
    
    articles = [
        {
            "title": entry.get("title", "No title"),
            "link": entry.get("link", "#")
        }
        for entry in feed.entries if "vulnerability" in entry.get("title", "").lower()
    ]
    
    return articles

def format_email_content(nvd, mitre, cisa, articles):
    def format_section(title, items, is_html=False):
        if not items:
            return f"<p><b>{title}:</b> No news today.</p>\n\n" if is_html else f"{title}: No news today.\n\n"
        
        if is_html:
            return f"<h3>{title}:</h3><ul>" + "".join([
                f"<li><b>{item.get('id', 'N/A')}</b> - {item.get('description', 'No description')} (CVSS: <b>{item.get('cvss', 'N/A')}</b>) - <a href='{item.get('link', '#')}'>More Info</a></li>"
                for item in items]) + "</ul>\n\n"
        else:
            return f"{title}:\n" + "\n".join([
                f"- {item.get('id', 'N/A')} - {item.get('description', 'No description')} (CVSS: {item.get('cvss', 'N/A')}) ({item.get('link', '#')})"
                for item in items]) + "\n\n"
    
    def format_articles(articles, is_html=False):
        if not articles:
            return "<p><b>Bleeping Computer Articles:</b> No relevant articles today.</p>\n\n" if is_html else "Bleeping Computer Articles: No relevant articles today.\n\n"
        
        if is_html:
            return "<h3>Bleeping Computer Articles:</h3><ul>" + "".join([
                f"<li><a href='{article.get('link', '#')}'>{article.get('title', 'No title')}</a></li>"
                for article in articles]) + "</ul>\n\n"
        else:
            return "Bleeping Computer Articles:\n" + "\n".join([
                f"- {article.get('title', 'No title')} ({article.get('link', '#')})"
                for article in articles]) + "\n\n"
    
    content_html = """
    <html>
    <body>
    <h2>Daily Cybersecurity Threat Report</h2>
    <hr>
    """
    content_html += format_section("NVD CVEs", nvd, is_html=True)
    content_html += format_section("MITRE CVEs", mitre, is_html=True)
    content_html += format_section("CISA Exploited CVEs", cisa, is_html=True)
    content_html += format_articles(articles, is_html=True)
    content_html += "</body></html>"
    
    return content_html

def send_email(subject, body, recipient):
    sender_email = "SENDER_EMAIL" #change sender email
    sender_password = "SENDER_PASSWORD" #change your password
    
    sent_from = sender_email
    to = [recipient]
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))
    
    try:
        server = smtplib.SMTP_SSL('smtp.zoho.com', 465) #change your smtp config
        server.login(sender_email, sender_password)
        server.sendmail(sent_from, to, msg.as_string())
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
    send_email("Daily Cybersecurity Report", email_content, "YOUR_EMAIL") #add your email
    
if __name__ == "__main__":
    main()

