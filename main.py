#Libreries

import streamlit as st
import requests
import re
import ipaddress
from collections import Counter
import random
import string
import streamlit.components.v1 as com

st.set_page_config(page_title="🛡️ Cybersecurity Toolkit")


#IP Analyze Start----------------------------------------------------------------------------------------------
tool_selection = st.sidebar.radio("Choose an analyzer:", ("🌐IP Analyzer", "🔐Password Analyzer", "🔐Password Generator", "📧Phishing Analyzer", "🔗URL Analyzer","📥Log File"), index=None)
if tool_selection==None:
    com.iframe("https://embed.lottiefiles.com/animation/9101", height=100, scrolling=True)
    st.title("Welcome to the Ultimate Cybersecurity Toolkit!")
    st.markdown("""


|**_🌐 IP Analyzer|
|🔐 Password Analyzer|  
|🔐 Password Generator| 
|📧 Phishing Analyzer|  
|🔗 URL Analyzer|   
|📥 Log File Analyzer_**|
""")
    st.info("This toolkit is designed to provide insights and analysis for various cybersecurity aspects. Please select a tool from the sidebar to begin your analysis.")
    
if tool_selection == "🌐IP Analyzer":
    com.iframe("https://embed.lottiefiles.com/animation/9203", height=100, scrolling=True)

    st.title("🌐 IP Analyzer")
    st.subheader("Enter an IP address to analyze its details and potential threats.")

    if st.button("Get My IP Address"):
        try:
            ip = requests.get("https://api.ipify.org")
            st.info(f"Your Public IP: {ip.text}")
        except:
            st.error("Unable to detect IP address. Please check your internet connection and try again.")

    ip=st.text_input("Enter IP Address",placeholder="e.g., 255.255.255.255",help="Enter a valid IPv4 or IPv6address to analyze its details and potential threats.")

    if st.button("Analyze IP"):
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError:
            parsed_ip = None

        if parsed_ip:
                if parsed_ip.version == 4:
                    st.info("This IP format is valid IPv4.")
                else:
                    st.info("This IP format is valid IPv6.")
            
                with st.spinner("Fetching IP details..."):
                    response = requests.get(f"http://ip-api.com/json/{ip}")
                    data = response.json()
                    if data["status"] != "success":
                        st.error("Failed to fetch IP details. Please check the IP address and try again.")
                        st.stop()
                        
                    else:
                        st.subheader("IP Details:")
                        tab1, tab2,tab3 = st.tabs(["Details", "Threat Analysis", "MAP"])
                        with tab1:
                            st.metric(f"**IP Address:** ",data['query'])
                            col1,col2=st.columns(2)
                            with col1:
                                st.metric(f"**ISP:** ",data['isp'])
                                st.metric(f"**City:** ",data['city'])
                                st.metric(f"**Region:** ",data['regionName'])
                                st.metric(f"**Timezone:** ",data['timezone'])
                            with col2:
                                st.metric(f"**Location (Lat, Lon):** ",f"{data['lat']}, {data['lon']}")
                                st.metric(f"**Organization:** ",data['org'])
                                st.metric(f"**Postal Code:** ",data['zip'])
                                st.metric(f"**Country:** ",data['country'])
                                
                        with tab2:
                                col1,col2,col3=st.columns(3)
                                with col1:
                                    st.metric(f"**IP Version:** ", "IPv4" if parsed_ip.version == 4 else "IPv6")
                                    st.metric(f"**Is Private:** ",parsed_ip.is_private)
                                    st.metric(f"**Is Global:** ",parsed_ip.is_global)
                                    
                                with col2:
                                  
                                    st.metric(f"**Is Loopback:** ",parsed_ip.is_loopback)
                                    st.metric(f"**Multicast IP:** ",parsed_ip.is_multicast)
                                    st.metric(f"**Reserved IP:** ",parsed_ip.is_reserved)
                                with col3:
                                    net = ipaddress.ip_network("192.168.1.0/24")

                                    st.metric(f"**Netmask:** ",str(net.netmask))
                                    st.metric(f"**Network Address:** ",str(net.network_address))
                                    st.metric(f"**Broadcast Address:** ",str(net.broadcast_address))
                        with tab3:
                            st.map({"lat": [data['lat']], "lon": [data['lon']]}, zoom=10,height=400)
                        
                        isp=data['isp'].lower()
                        org=data['org'].lower()
                        combined_info=isp+" "+org

                        high_risk = ["hosting","vps","datacenter","data center","cloud computing","virtual server","dedicated server","colo","colocation","digitalocean","ovh","hetzner","vultr","linode","contabo"]
                        medium_risk = ["cloud","compute","infrastructure","edge network","cdn","akamai","cloudflare","fastly","aws","azure","google cloud"]
                        vpn_risk = ["vpn","proxy","anonymous","tor","exit node","relay"]
                        
                        if any(term in combined_info for term in high_risk):
                            st.warning("🚨 High-risk IP detected!")
                        elif any(term in combined_info for term in medium_risk):
                            st.warning("⚠️ Medium-risk IP detected!")
                        elif any(term in combined_info for term in vpn_risk):
                            st.warning("⚠️ Potential VPN or proxy detected!")                  
                        else:
                            st.success("This IP address does not appear to be associated with any known hosting providers, VPN services, or other potentially suspicious activity based on the ISP and organization information.", icon="✅")
                       
        else:
                st.error("Invalid IP address format. Please enter a valid IPv4 or IPv6 address.")
                st.info("IPv4 addresses consist of four octets separated by dots "
                "(e.g., 192.168.1.1)." 
                "IPv6 addresses consist of eight groups of four hexadecimal digits separated by colons"
                "(e.g., 2001:0db8:85a3:0000:0000:8a2e:0370:7334).")

#IP Analyze End------------------------------------------------------------------------------------------------
#Password Analyzer Start----------------------------------------------------------------------------------------------
elif tool_selection == "🔐Password Analyzer":
    com.iframe("https://embed.lottiefiles.com/animation/108", height=100, scrolling=True)
    st.title("🔐 Password Analyzer")
    st.subheader("Enter a password to analyze its strength and potential vulnerabilities.")

    password = st.text_input("Enter Password", type="password", placeholder="e.g., P@ssw0rd123", help="Enter a password to analyze its strength and potential vulnerabilities. A strong password typically includes a mix of uppercase and lowercase letters, numbers, and special characters, and is at least 12 characters long.")

    if st.button("Analyze Password"):
        if not password:
            st.error("Please enter a password to analyze.")
        else:
            score=0
            improvements=[]
            if len(password) > 8:
                score+=1
            else:
                improvements.append("Increase password length to at least 8 characters.")
            if any(c.islower() for c in password):
                score+=1
            else:
                improvements.append("Include lowercase letters.")
            if any(c.isupper() for c in password):
                score+=1   
            else:
                improvements.append("Include uppercase letters.")
            if any(c.isdigit() for c in password):
                score+=1
            else:
                improvements.append("Include numbers.")
            if any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/" for c in password):
                score+=1
            else:
                improvements.append("Include special characters.")
            if re.search(r"(.)\1\1", password):
                improvements.append("Avoid repeating characters.")
            
            common_passwords = ["password", "123456", "123456789", "qwerty", "abc123", "football", "monkey", "letmein", "111111", "1234"]
            if password.lower() in common_passwords:
                improvements.append("Avoid common passwords.")
            st.progress(score/5)
            if score == 5:
                st.success("✅ Your password is very strong! Keep it up!")
            elif score ==4:
                st.warning("⚠️ Your password is strong, but it could be improved by following these suggestions:")
            elif score ==3:
                st.warning("⚠️ Your password is moderate, and it could be improved by following these suggestions:")
            elif score ==2:
                st.warning("⚠️ Your password is weak, and it should be improved by following these suggestions:")
            else:
                st.error("❌ Your password is very weak, and it must be improved by following these suggestions:")
            
            for improvement in improvements:
                st.write(f" - {improvement}")
               
#Password Analyzer End------------------------------------------------------------------------------------------------
# Password Generator Start----------------------------------------------------------------------------------------------
elif tool_selection == "🔐Password Generator":
    com.iframe("https://embed.lottiefiles.com/animation/711", height=100, scrolling=True)
    st.subheader("Generate a Strong Password")
    password_length = st.slider("Password Length",8,32,16,help="Select the desired length for your generated password. A longer password is generally more secure, with 16 characters being a good choice for strong security.")
    include_uppercase = st.checkbox("Include Uppercase Letters", value=True)
    include_lowercase = st.checkbox("Include Lowercase Letters", value=True)
    include_numbers = st.checkbox("Include Numbers", value=True)
    include_special = st.checkbox("Include Special Characters", value=True)
   
    if st.button("Generate Password"):
        characters = ""
        if include_uppercase:
            characters += string.ascii_uppercase
        if include_lowercase:
            characters += string.ascii_lowercase
        if include_numbers:
            characters += string.digits
        if include_special:
            characters += string.punctuation

        if not characters:
            st.error("Please select at least one character type to include in the password.")
        else:
            generated_password = ''.join(random.choice(characters) for i in range(0,password_length))
            st.success(f"Generated Password: {generated_password}")
# Password Generator End------------------------------------------------------------------------------------------------
#Phishing Analyzer Start----------------------------------------------------------------------------------------------

elif tool_selection == "📧Phishing Analyzer":
    com.iframe("https://embed.lottiefiles.com/animation/7211", height=100, scrolling=True)
    st.title("📧 Phishing Analyzer")
    st.subheader("Enter an email address to analyze its potential phishing risks.")

    email = st.text_input("Enter Email Address", placeholder="e.g.,xyz321@gmail.com", help="Enter an email address to analyze its potential phishing risks. Phishing emails often use deceptive sender addresses, urgent language, and may contain suspicious links or attachments. Analyzing the email address can help identify potential red flags associated with phishing attempts.")
    if st.button("Analyze Email"):
        if not email:
            st.error("Please enter an email address to analyze.")
        else:
            desposable_domains = ["mailinator.com", "10minutemail.com", "guerrillamail.com", "temp-mail.org", "yopmail.com", "trashmail.com", "fakeinbox.com", "getnada.com", "dispostable.com", "tempmail.net"]
            domain = email.split('@')[1]
            if domain in desposable_domains:
                st.warning("⚠️ This email address is from a known disposable email provider, which is often used for temporary or anonymous accounts. Be cautious when interacting with emails from this address, as it may be associated with phishing attempts.")
            domain_similarity = ["gamil.com", "gnail.com", "hotmial.com", "yaho.com", "outlok.com", "icloud.con", "gmial.com", "yahho.com", "outllok.com", "icoud.com"]
            if domain in domain_similarity:
                st.warning("⚠️ This email address has a domain that is similar to a common email provider, which could be an attempt to deceive recipients. Be extra cautious and verify the sender's identity before engaging with any emails from this address.")
            
            if re.match(r"^\w+@\w+\.\w+", email):
                st.success("✅ The email address format is valid.")
                domain = email.split('@')[1]
                if domain in ["gmail.com", "yahoo.com", "outlook.com",'icloud.com'] or domain.endswith(".edu") or domain.endswith(".gov") or domain.endswith(".in") or domain.endswith(".org"):
                    st.info("This is a common email provider, which may be less likely to be used for phishing. However, always be cautious and verify the sender's identity.")
                else:
                    st.warning("⚠️ This email address uses a less common domain, which could be a red flag for phishing. Be extra cautious and verify the sender's identity before engaging with any emails from this address.")
            else:
                st.error("❌ The email address format is invalid. Please enter a valid email address.")          
#Phishing Analyzer End------------------------------------------------------------------------------------------------
# URL Analyzer Start----------------------------------------------------------------------------------------------
elif tool_selection == "🔗URL Analyzer":
    com.iframe("https://embed.lottiefiles.com/animation/7242", height=100, scrolling=True)
    st.title("🔗 URL Analyzer")
    st.subheader("Enter a URL to analyze its potential risks and details.")

    url = st.text_input("Enter URL", placeholder="e.g., https://www.example.com", help="Enter a URL to analyze its potential risks and details. A URL analyzer can help identify if the link is safe, if it uses HTTPS, if it's associated with known phishing sites, and other important information that can help you stay safe online.")
    
    if st.button("Analyze URL"):
        if not url:
            st.error("Please enter a URL to analyze.")
        else:
            problems=0
            Warning=[]
            
            if not re.match(r"https?:\/\/\S+",url):
                st.error("❌ The URL format is invalid. Please enter a valid URL starting with http:// or https://")   
            else:
                st.success("✅ The URL format is valid.")
                if not url.startswith("https://"):
                    problems+=1
                    Warning.append("This URL uses HTTP, which is less secure than HTTPS. However, always be cautious and verify the legitimacy of the website before entering any sensitive information.")
                
                if re.search(r"@\w+", url):
                    problems+=1
                    Warning.append("⚠️ The URL contains an '@' symbol, which can be a red flag for phishing attempts. Be cautious and verify the legitimacy of the website before clicking on any links or entering sensitive information.")
                                               
                if re.search(r"\.\w{2,}$", url):
                    domain = re.search(r"\.\w{2,}$", url).group()
                    if domain in [".com", ".net", ".org", ".edu", ".gov"]:
                        st.info("This URL uses a common top-level domain (TLD), which may be less likely to be associated with phishing. However, always be cautious and verify the legitimacy of the website before engaging with it.")
                    else:
                        problems+=1
                        Warning.append("⚠️ The URL uses an uncommon top-level domain (TLD), which can be a red flag for phishing attempts. Be cautious and verify the legitimacy of the website before clicking on any links or entering sensitive information.")
                    
                if len(url)>75:
                    problems+=1
                    Warning.append("⚠️ The URL is unusually long, which can be a red flag for phishing attempts. Be cautious and verify the legitimacy of the website before clicking on any links or entering sensitive information.")
                if re.search(r"[^a-zA-Z0-9:/?&=._-]", url):
                    problems+=1
                    Warning.append("⚠️ The URL contains unusual characters, which can be a red flag for phishing attempts. Be cautious and verify the legitimacy of the website before clicking on any links or entering sensitive information.")
                if url.count(".") > 3:
                    problems+=1
                    Warning.append("⚠️ The URL contains multiple subdomains, which can be a red flag for phishing attempts. Be cautious and verify the legitimacy of the website before clicking on any links or entering sensitive information.")
                
                if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
                    problems+=1
                    Warning.append("⚠️ The URL contains an IP address instead of a domain name, which can be a red flag for phishing attempts. Be cautious and verify the legitimacy of the website before clicking on any links or entering sensitive information.")

                suspicious_keywords = ["login", "secure", "account", "update", "verify", "password", "bank", "paypal", "ebay", "amazon"]
                if any(keyword in url.lower() for keyword in suspicious_keywords):
                    problems+=1
                    Warning.append("⚠️ The URL contains suspicious keywords that are commonly used in phishing attempts. Be cautious and verify the legitimacy of the website before clicking on any links or entering sensitive information.")
                
                if problems==0:
                    st.success("This URL does not appear to have any obvious red flags for phishing. However, always be cautious and verify the legitimacy of the website before engaging with it.")
                else:
                    st.warning(f"⚠️ This URL has {problems} potential red flags for phishing. Please review the following warnings and exercise caution when interacting with this URL:")
                    for warning in Warning:
                        st.write(f" - {warning}")
# URL Analyzer End------------------------------------------------------------------------------------------------
# Log File Analyzer Start----------------------------------------------------------------------------------------------
elif tool_selection == "📥Log File":
    com.iframe("https://embed.lottiefiles.com/animation/7249", height=100, scrolling=True)
    st.title("📥 Log File Analyzer")
    st.subheader("Upload a log file to analyze its contents for potential security issues.")

    uploaded_file = st.file_uploader("Choose a log file", type=["log", "txt"], help="Upload a log file to analyze its contents for potential security issues. Log files can contain valuable information about system events, user activities, and potential security incidents. Analyzing log files can help identify patterns, detect anomalies, and enhance overall security monitoring.")
    
    if st.button("Analyze Log File"):
        if not uploaded_file:
            st.error("Please upload a log file to analyze.")
        else:
            st.success("Log file uploaded successfully! Analyzing contents...")
            log_contents = uploaded_file.getvalue().decode("utf-8", errors="ignore")

            ip=re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", log_contents)
            ip_counts=Counter(ip)
            st.subheader("IP Address Analysis:")

            if not ip_counts:
                st.info("No IP addresses found in the uploaded log file.")
            else:
                for ip, count in ip_counts.items():
                    st.write(f"**{ip}** - {count} occurrences")
                            
# Log File Analyzer End------------------------------------------------------------------------------------------------

