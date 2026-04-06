<div align="center">
  <h1>VENO FRAMEWORK V3.0</h1>
</div>

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)](https://golang.org/)
[![Rust Plugins](https://img.shields.io/badge/Rust-Hot--Reload-DEA584?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Veno_License-blue.svg?style=flat-square)](LICENSE)

Veno, modern web uygulamaları ve mikroservis mimarileri için tasarlanmış, konfigürasyon odaklı bir **Edge Gateway (Sınır Geçidi)** ve **Reverse Proxy (Ters Vekil Sunucu)** çözümüdür. 

Kapalı altyapı optimizasyonlarının ardından, mimarisi baştan aşağı yenilenen Veno, **v3.0 sürümüyle ilk kez açık kaynak dünyasına sunulmaktadır.** Geleneksel web sunucularının (Nginx, HAProxy) çalışma hızı ile modern dillerin güvenlik avantajlarını birleştiren Veno; Go dilinin yüksek eşzamanlılık (concurrency) gücünü omurga olarak kullanırken, Rust dilinin bellek güvenliğini çalışma anı (runtime) eklentileriyle sisteme dahil eder.

Veno'nun en büyük vizyonu, karmaşık ağ güvenlik politikalarını ve yük dengeleme algoritmalarını, geliştirici dostu (Developer-Friendly) ve estetik bir kurulum süreciyle tek bir komuta indirgemektir.

---

## 1. Mimari Felsefe ve İstek Yaşam Döngüsü

Bir "API Gateway", uygulamanız ile dış dünya arasındaki ön kapı, aynı zamanda en güçlü muhafızdır. Veno, gelen her bir HTTP isteğini uygulamanıza (arka uca) ulaşmadan önce katı bir güvenlik ve performans zincirinden geçirir.

**Trafik Akışı:**
İnternet ➔ [Trafik Sınırlandırıcı] ➔ [Güvenlik Duvarı/WAF] ➔ [Rust Eklentileri] ➔ [Önbellek] ➔ [Devre Kesici] ➔ Sizin Uygulamanız

Veno'yu farklı kılan şey, bu zincirdeki her halkanın bağımsız çalışabilmesi ve sistemin tamamen durdurulmadan (zero-downtime) güncellenebilmesidir. Sistem yönetimi kod kalabalığından arındırılmış, birkaç sade TOML dosyasını düzenlemek kadar basit bir hale getirilmiştir.

---

## 2. Temel Özellikler: Ne, Neden ve Nasıl?

### 2.1. Dinamik Rust Eklentileri (Hot-Swapping FFI)
Normalde bir sunucunun çalışma mantığını değiştirmek için kodu yeniden derlemeniz ve sunucuyu yeniden başlatmanız gerekir. Bu da saniyeler veya dakikalar süren kesintiler demektir.
* **Ne Yapar?** Veno, siz sunucuyu kapatmadan yeni kurallar ve iş mantıkları (business logic) eklemenize olanak tanır.
* **Nasıl Çalışır?** plugins/ klasörüne bıraktığınız bir Rust eklenti (.rs) kodunu anında algılar, arka planda derler ve milisaniyeler içinde mevcut çalışan sisteme enjekte eder. Bağlantılar kopmaz, trafik kesintiye uğramaz.
* **Kullanım:** Gelen isteklerdeki kredi kartı numaralarını maskelemek, özel kimlik doğrulama sistemleri (Custom Auth) kurmak veya belirli coğrafi konumlara anlık kısıtlamalar getirmek için idealdir.

### 2.2. Yerleşik Güvenlik Duvarı (Dahili WAF)
Dışarıdan ek bir yazılıma ihtiyaç duymadan, gelen kötü niyetli istekleri sunucunun kapısında engeller.
* Uygulamanıza yapılmaya çalışılan veritabanı sızıntısı (SQL Injection), zararlı script çalıştırma (XSS) veya Dizin Atlama (Path Traversal) girişimlerini, gelen isteğin metnini analiz ederek anında tespit eder ve 403 Yasak yanıtı ile geri çevirir.
* Projenizin risk durumuna göre 4 farklı güvenlik profili sunar: Finans/Sağlık projeleri için tavizsiz (strict), standart uygulamalar için dengeli (normal), şirket içi ağlar için esnek (relaxed) ve sadece analiz/log yapan test modu (dev).

### 2.3. Devre Kesici (Circuit Breaker) & Sağlık Kontrolü
Arka planda çalışan uygulamanız (örneğin veritabanınız veya ödeme servisiniz) çöktüğünde, sistemin tamamen kilitlenmesini önler.
* Tıpkı evinizdeki elektrik sigortası gibi çalışır. Arka uçtaki servis peş peşe hata vermeye başladığında Veno "sigortayı attırır" ve o servise giden trafiği geçici olarak keser. Zincirleme çöküşleri (Cascading Failures) engeller.
* Arka planda servisi sürekli "Nasılsın?" diye yoklar (Health Check). Servis düzeldiğinde sigortayı otomatik olarak tekrar açar ve trafiği normale döndürür.

### 2.4. Aktif Bellek Bekçisi (Memory Warden)
Sunucular uzun süre yoğun yük altında çalıştığında şişebilir ve RAM yetersizliğinden (OOM) dolayı işletim sistemi tarafından sonlandırılabilir. 
* Veno, kendi RAM tüketimini sürekli izler. Sizin belirlediğiniz sınıra (örneğin 512MB) yaklaştığında, hafızasında tuttuğu en eski ve önemsiz verileri (LRU Cache) otomatik olarak tahliye eder ve sistemi rahatlatır. Bellek yönetimi tamamen Veno'nun kontrolündedir.

---

## 3. Akıllı Kurulum ve Hızlı Başlangıç

Veno, geliştirici deneyimini (DX) en üst düzeye çıkarmak için tasarlanmıştır. Karmaşık derleme süreçleri ve saatlerce süren manuel yapılandırmalar yerine, Python ile yazılmış özel **Proje Oluşturucu (Initializer)** betiği sayesinde saniyeler içinde tamamen size özel bir Gateway mimarisi ayağa kaldırabilirsiniz.

**Otomatik Kurulum Adımları:**

1. **İndir ve Yerleştir:** Veno proje oluşturucu betiğini (veno_init.py) projeyi başlatmak istediğiniz boş bir dizine indirin veya kopyalayın.
2. **Sihirbazı Başlat:** Terminalinizden betiği çalıştırın (örneğin: python3 veno_init.py). Karşınıza estetik ve interaktif bir terminal arayüzü çıkacaktır.
3. **Özelleştir:** Kurulum sihirbazının size soracağı temel ayarları (Proje Adı, Port, Gelişmiş Güvenlik Profili, Cache Limitleri) kendi ihtiyacınıza göre yanıtlayın.

Betiğin çalışması tamamlandığında; Veno sizin için tüm güvenli klasör hiyerarşisini, sandbox kilitlerini (.veno/root.lock), modüler TOML konfigürasyonlarını, özel hata sayfalarını ve Make otomasyon şablonunu anında üretecektir. 

Kurulum bittikten sonra doğrudan üretilen klasöre girip sunucunuzu anında başlatabilirsiniz! (Derleme ve çalıştırma için sisteminizde Go 1.22+ yüklü olmalıdır).

---

## 4. Konfigürasyon Yapısı (Sistem Nasıl Yönetilir?)

Sistemin yönetimi Go kodlarının içinde değil, config/ dizininde bulunan, okunması ve düzenlenmesi son derece kolay olan TOML dosyalarındadır.

* **app.toml:** Sunucunun hangi portta dinleme yapacağı, HTTPS (TLS) sertifika yolları ve donanım/bellek limitleri burada belirlenir.
* **security.toml:** "Hangi IP'ler engellenecek?", "Bir kullanıcı saniyede kaç istek atabilir?", "CORS politikaları ne olacak?" gibi güvenlik kuralları buradan yönetilir.
* **routes.toml:** Veno'ya gelen bir isteğin arka planda hangi sunucuya yönlendirileceği (Upstream) ve yük dağıtımı (Load Balancing) ayarları burada yapılır.
* **env.toml:** Veritabanı şifreleri, API anahtarları veya özel kilitler gibi hassas veriler burada durur. (Bu dosya otomatik oluşturulan .gitignore sayesinde Git geçmişine eklenmez, tamamen size ve yerel sunucunuza özel kalır).

---

## 5. İzleme ve Metrikler (Observability)

Sistemin o anki durumunu gerçek zamanlı görmek için Veno size dışa kapalı iki hazır kontrol noktası sunar:
* GET /__veno/health: Sunucu ayakta mı ve istek alabiliyor mu? (Yük dengeleyiciler ve sistem yöneticileri için hızlı ping noktası).
* GET /__veno/metrics: O an kaç aktif sunucu çalışıyor, bellek kullanımı ne durumda, önbellek isabet oranı (Cache Hit/Miss) nedir, WAF tarafından engellenen istek sayısı kaç? Bu verileri saniyelik olarak yapılandırılmış JSON formatında size iletir.

---

## 6. Lisans (Veno License)

Bu yazılım, geliştiricilerin özgürlüğünü merkeze alan **Veno License** ile lisanslanmıştır. Temel yapısı itibarıyla açık kaynak dünyasının en özgürlükçü standartlarını benimser:

* Projeyi **ticari amaçlarla**, kurumsal şirketlerinizde veya kapalı kaynak (closed-source) projelerinizde **tamamen ücretsiz** olarak kullanabilir, kopyalayabilir ve değiştirebilirsiniz.
* Uygulamayı sunucularınıza kurarken veya müşterilerinize satarken hiçbir izin almanıza veya kaynak kodunuzu açmanıza gerek yoktur.

**Tek Geçerli Şart:**
Veno'nun kaynak kodlarını değiştirerek, geliştirerek veya çatallayarak (fork) yeni bir **açık kaynak (open-source)** araç veya kütüphane olarak internette dışarıya yayınlayacaksanız; yeni projenin isminde veya temel mimari atıflarında **"Veno" isminin korunması/belirtilmesi zorunludur.** (Örneğin: *Veno-Lite*, *Veno Custom Edge*, *Powered by Veno* vb.)

Bunun dışında hiçbir kısıtlama veya gizli madde yoktur. Özgürce kodlayın, özgürce kazanın.

<br>
<div align="center">
  <i>Mühendislik, karmaşıklığı saklama ve güvenilirliği sağlama sanatıdır.</i>
</div>
