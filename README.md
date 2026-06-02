# 🔍 ADScan — Active Directory Security Analysis Tool

> Kali Linux üzerinde çalışan, Active Directory ortamlarını otomatik olarak tarayan ve güvenlik açıklarını raporlayan açık kaynaklı bir güvenlik analiz aracı.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-purple?style=flat-square&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.0-red?style=flat-square)

---

## 📌 Nedir?

ADScan, Microsoft Active Directory ortamlarındaki güvenlik açıklarını tespit etmek için geliştirilmiş taşınabilir bir güvenlik denetim aracıdır. Kali Linux üzerinde çalışır, hedef domain'e bağlanır ve **50 farklı güvenlik kontrolü** gerçekleştirerek sonuçları interaktif bir HTML raporu olarak sunar.

> ⚠️ Bu araç yalnızca **yetkili güvenlik değerlendirmeleri** için tasarlanmıştır. İzinsiz sistemlerde kullanımı yasa dışıdır.

---

## ✨ Özellikler

- 🔎 **Otomatik ağ keşfi** — Nmap ile DC tespiti
- 📋 **LDAP envanteri** — Kullanıcı, grup, bilgisayar ve GPO listesi
- 🎯 **50 güvenlik kontrolü** — Kerberoasting, AS-REP Roasting, zayıf parola politikası, atıl hesaplar ve daha fazlası
- 📊 **İnteraktif HTML raporu** — Güvenlik skoru, grafikler, öncelikli bulgular
- 📚 **Security Knowledge Base** — 50 zafiyetin tamamının açıklaması, çözümü ve MITRE ATT&CK eşlemesi
- 🌐 **Web arayüzü** — `localhost:8080` üzerinden tüm raporlara erişim
- 🖨️ **PDF export** — Raporları PDF olarak kaydetme
- 🎛️ **Seçici tarama** — Belirli kontrol gruplarını veya tek bir kontrolü çalıştırma

---

## 🛡️ Güvenlik Kontrol Kategorileri

| Kategori | Kontrol Sayısı | Örnek |
|----------|---------------|-------|
| Kerberos | 5 | Kerberoasting, AS-REP Roasting, Golden Ticket riski |
| Password Policy | 8 | Minimum uzunluk, lockout, karmaşıklık |
| Privileged Accounts | 9 | Domain Admin sayısı, shadow admin, guest hesap |
| Service Accounts | 4 | SPN hesapları, paylaşılan hesaplar |
| Account Hygiene | 9 | Atıl hesaplar, açıklamada şifre, RC4 şifreleme |
| System Security | 6 | EOL işletim sistemi, SMBv1, WinRM |
| Group Policy | 2 | GPO sayısı, boş GPO |
| Domain Config | 7 | Domain functional level, recycle bin, trust |

---

## ⚙️ Kurulum

**Gereksinimler:** Kali Linux, Python 3.8+, Nmap

```bash
# Repoyu klonla
git clone https://github.com/MuharremA/ad_analyzer.git
cd ad_analyzer

# Kurulumu çalıştır
bash install.sh
```

---

## 🚀 Kullanım

### Tam tarama (önerilen)
```bash
bash run.sh
```

### Manuel tam tarama
```bash
python3 ad_analyzer.py \
  --dc <DC_IP_ADRESI> \
  --domain <DOMAIN_ADI> \
  -u <KULLANICI_ADI> \
  -p '<SIFRE>'
```

### Kategori bazlı tarama
```bash
# Kerberos kontrolleri
python3 ad_analyzer.py --dc <DC_IP> --domain <DOMAIN> -u <USER> -p '<PASS>' -cg kerberos

# Parola politikası kontrolleri
python3 ad_analyzer.py --dc <DC_IP> --domain <DOMAIN> -u <USER> -p '<PASS>' -cg password

# Ayrıcalıklı hesap kontrolleri
python3 ad_analyzer.py --dc <DC_IP> --domain <DOMAIN> -u <USER> -p '<PASS>' -cg privileged

# Servis hesabı kontrolleri
python3 ad_analyzer.py --dc <DC_IP> --domain <DOMAIN> -u <USER> -p '<PASS>' -cg serviceaccount

# Hesap hijyeni kontrolleri
python3 ad_analyzer.py --dc <DC_IP> --domain <DOMAIN> -u <USER> -p '<PASS>' -cg user

# Sistem güvenliği kontrolleri
python3 ad_analyzer.py --dc <DC_IP> --domain <DOMAIN> -u <USER> -p '<PASS>' -cg system

# Domain yapılandırma kontrolleri
python3 ad_analyzer.py --dc <DC_IP> --domain <DOMAIN> -u <USER> -p '<PASS>' -cg domain
```

### Belirli kontrol taraması
```bash
# Tek kontrol (örn: 27. kontrol — açıklamada şifre)
python3 ad_analyzer.py --dc <DC_IP> --domain <DOMAIN> -u <USER> -p '<PASS>' -c 27

# Aralık tarama (örn: 1-5 arası kontroller)
python3 ad_analyzer.py --dc <DC_IP> --domain <DOMAIN> -u <USER> -p '<PASS>' -c 1-5
```

### Raporları görüntüleme
```bash
# Rapor sunucusunu başlat (ayrı terminal)
python3 rapor_server.py

# Tarayıcıda aç
# http://localhost:8080
```

---

## 📁 Proje Yapısı

```
ad_analyzer/
├── ad_analyzer.py       # Ana çalıştırma dosyası ve CLI
├── install.sh           # Kurulum scripti
├── run.sh               # Hızlı çalıştırma kısayolu
├── rapor_server.py      # Web rapor sunucusu (port 8080)
└── modules/
    ├── scanner.py       # Nmap ile ağ keşfi ve DC tespiti
    ├── collector.py     # LDAP ile AD verisi toplama
    ├── analyzer.py      # 50 güvenlik kontrolü
    └── reporter.py      # İnteraktif HTML rapor üretimi
```

---

## 📊 Rapor İçeriği

### Sayfa 1 — Scan Report
- Executive Summary (güvenlik skoru, grade, bulgu özeti)
- Risk dağılım grafikleri
- Güvenlik bulguları (severity'e göre sıralı)
- Remediation Summary (öncelik sırasına göre çözüm adımları)
- Envanter tabloları (kullanıcılar, bilgisayarlar, gruplar, SPN hesapları)
- 50 kontrolün tamamının tarama sonucu

### Sayfa 2 — Security Knowledge Base
- 50 zafiyetin detaylı açıklaması
- Her zafiyet için adım adım çözüm (PowerShell komutları ile)
- MITRE ATT&CK eşlemesi (tıklanabilir linkler)
- Kategori ve arama filtresi

---

## 🔒 Ağ Gereksinimleri

ADScan, LDAP (port 389) ve Kerberos (port 88) protokollerini kullanır. Bu protokoller sadece yerel ağda çalışır. Bu nedenle:

- Tarama yapan cihazın hedef AD ortamıyla **aynı ağda** olması gerekir
- Uzaktan tarama için **VPN bağlantısı** kullanılabilir
- Müşteri ortamı taramalarında DC IP adresi, domain adı ve yetkili kullanıcı bilgileri müşteri tarafından sağlanır

---

## 📄 Lisans

Bu proje [MIT License](LICENSE) ile lisanslanmıştır.

---

<p align="center">
  Yeditepe Üniversitesi — Bilgi Güvenliği Teknolojisi Bölümü Bitirme Projesi
</p>
