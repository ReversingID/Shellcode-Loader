# Shellcode Loader

### Overview

Melakukan penyalahgunaan windows API untuk mengeksekusi shellcode sebagai callback.

Sebagian windows API menerima callback yang akan dijalankan untuk menangani objek atau memproses hasil operasi. Dengan menjalankan shellcode sebagai callback, kode menjadi lebih tersamarkan karena pemanggilan shellcode menjadi implisit.

Umumnya callback akan berjalan pada thread yang sama dengan thread yang memanggil fungsi windows API.

Variasi dalam katalog ini dikelompokkan berdasarkan karakteristik API pemanggil: pola enumerasi, I/O asinkron, hook pesan, dialog/UI, multimedia, kriptografi, loader/modul, notifikasi jaringan, dan lainnya.

### Catalog

**Enumerasi window / desktop**

- [EnumWindows](EnumWindows): enumerasi top-level window di desktop.
- [EnumChildWindows](EnumChildWindows): enumerasi window anak dari parent HWND.
- [EnumDesktopWindows](EnumDesktopWindows): enumerasi window pada desktop tertentu.
- [EnumDesktops](EnumDesktops): enumerasi desktop di window station aktif.
- [EnumWindowStations](EnumWindowStations): enumerasi window station di sesi.
- [EnumThreadWindows](EnumThreadWindows): enumerasi window milik thread tertentu.

**Enumerasi kalender / tanggal / waktu**

- [EnumCalendarInfo](EnumCalendarInfo): enumerasi informasi kalender sistem.
- [EnumCalendarInfoEx](EnumCalendarInfoEx): varian extended `EnumCalendarInfo`.
- [EnumCalendarInfoExEx](EnumCalendarInfoExEx): varian extended dengan filter locale tambahan.
- [EnumDateFormats](EnumDateFormats): enumerasi format tanggal yang didukung.
- [EnumDateFormatsEx](EnumDateFormatsEx): varian extended `EnumDateFormats`.
- [EnumDateFormatsExEx](EnumDateFormatsExEx): varian extended dengan filter locale tambahan.
- [EnumTimeFormats](EnumTimeFormats): enumerasi format waktu yang didukung.
- [EnumTimeFormatsEx](EnumTimeFormatsEx): varian extended `EnumTimeFormats`.

**Enumerasi locale / bahasa**

- [EnumLanguageGroupLocales](EnumLanguageGroupLocales): enumerasi locale dalam language group.
- [EnumSystemCodePages](EnumSystemCodePages): enumerasi code page yang terinstal.
- [EnumSystemGeoID](EnumSystemGeoID): enumerasi geographic location ID.
- [EnumSystemLanguageGroups](EnumSystemLanguageGroups): enumerasi language group sistem.
- [EnumSystemLocales](EnumSystemLocales): enumerasi locale yang terinstal.
- [EnumSystemLocalesEx](EnumSystemLocalesEx): varian extended `EnumSystemLocales`.
- [EnumUILanguages](EnumUILanguages): enumerasi bahasa antarmuka pengguna.

**Enumerasi GDI / font**

- [EnumFontFamilies](EnumFontFamilies): enumerasi keluarga font pada device context.
- [EnumFontFamiliesEx](EnumFontFamiliesEx): varian extended `EnumFontFamilies`.
- [EnumFonts](EnumFonts): enumerasi font pada device context.
- [EnumMetaFile](EnumMetaFile): enumerasi record di metafile.
- [EnumObjects](EnumObjects): enumerasi objek GDI (pen, brush, palette, dll.).

**Enumerasi resource PE**

- [EnumResourceLanguages](EnumResourceLanguages): enumerasi bahasa resource dalam modul/bin.
- [EnumResourceNames](EnumResourceNames): enumerasi nama resource dalam modul/bin.
- [EnumResourceNamesEx](EnumResourceNamesEx): varian extended `EnumResourceNames`.
- [EnumResourceTypes](EnumResourceTypes): enumerasi tipe resource dalam modul/bin.
- [EnumResourceTypesEx](EnumResourceTypesEx): varian extended `EnumResourceTypes`.

**Enumerasi lainnya**

- [EnumDirTree](EnumDirTree): enumerasi pohon direktori untuk pencarian simbol debug.
- [EnumDisplayMonitors](EnumDisplayMonitors): enumerasi monitor yang terhubung.
- [EnumPageFiles](EnumPageFiles): enumerasi page file sistem.
- [EnumProps](EnumProps): enumerasi property atom pada window.
- [EnumPropsEx](EnumPropsEx): varian extended `EnumProps`.
- [EnumPwrSchemes](EnumPwrSchemes): enumerasi skema daya sistem.
- [ImmEnumInputContext](ImmEnumInputContext): enumerasi input context IME pada window.

**I/O file asinkron**

- [ReadFileEx](ReadFileEx): completion routine setelah operasi baca overlapped.
- [WriteFileEx](WriteFileEx): completion routine setelah operasi tulis overlapped.
- [CopyFileEx](CopyFileEx): progress/completion callback selama penyalinan file.
- [CopyFile2](CopyFile2): progress callback pada API penyalinan file modern.

**Setup / instalasi**

- [SetupCommitFileQueue](SetupCommitFileQueue): handler callback antrian file Setup API.
- [PlaExtractCabinet](PlaExtractCabinet): callback ekstraksi cabinet Performance Logs.

**Hook / pesan window**

- [CallWindowProc](CallWindowProc): memanggil window procedure sebagai callback.
- [SendMessageCallback](SendMessageCallback): callback hasil `SendMessage` asinkron.
- [SetWinEventHook](SetWinEventHook): hook event aksesibilitas; callback saat event UI terjadi.
- [DialogBoxIndirectParam](DialogBoxIndirectParam): dialog procedure sebagai callback modal.

**Dialog / common control**

- [GetOpenFileName](GetOpenFileName): hook dialog pemilihan file (buka).
- [GetSaveFileName](GetSaveFileName): hook dialog pemilihan file (simpan).
- [ChooseColor](ChooseColor): hook dialog pemilihan warna.
- [ChooseFont](ChooseFont): hook dialog pemilihan font.
- [PrintDlg](PrintDlg): hook dialog cetak.
- [PageSetupDlg](PageSetupDlg): hook dialog pengaturan halaman.
- [CreatePropertySheetPage](CreatePropertySheetPage): callback pembuatan halaman property sheet.
- [PropertySheet](PropertySheet): callback property sheet wizard.
- [SHBrowseForFolder](SHBrowseForFolder): callback dialog browse folder Shell.

**Rendering / drawing callback**

- [DrawState](DrawState): callback rendering state (icon, bitmap, teks) via `DrawState`.
- [GrayString](GrayString): callback penggambaran string abu-abu.
- [LineDDA](LineDDA): callback digital differential analyzer untuk menggambar garis.

**Multimedia / audio**

- [waveOutOpen](waveOutOpen): callback event perangkat wave output.
- [waveInOpen](waveInOpen): callback event perangkat wave input.
- [acmDriverEnum](acmDriverEnum): enumerasi driver Audio Compression Manager.
- [mciSetYieldProc](mciSetYieldProc): yield procedure saat operasi MCI berjalan.
- [mmioInstallIOProc](mmioInstallIOProc): custom I/O procedure untuk operasi multimedia I/O.
- [DirectSoundEnumerate](DirectSoundEnumerate): enumerasi perangkat DirectSound.
- [DirectSoundCaptureEnumerate](DirectSoundCaptureEnumerate): enumerasi perangkat capture DirectSound.

**Kriptografi / sertifikat**

- [CryptDecodeMessage](CryptDecodeMessage): callback dekode pesan terenkripsi/CMS.
- [CryptEnumKeyIdentifierProperties](CryptEnumKeyIdentifierProperties): enumerasi properti key identifier.
- [CryptEnumOIDFunction](CryptEnumOIDFunction): enumerasi fungsi OID terdaftar.
- [CryptEnumOIDInfo](CryptEnumOIDInfo): enumerasi informasi OID kriptografi.
- [CryptInstallOIDFunctionAddress](CryptInstallOIDFunctionAddress): callback alamat fungsi OID kustom.
- [CryptVerifyMessageSignature](CryptVerifyMessageSignature): callback verifikasi tanda tangan pesan.
- [CertEnumPhysicalStore](CertEnumPhysicalStore): enumerasi physical certificate store.
- [CertEnumSystemStore](CertEnumSystemStore): enumerasi system certificate store.
- [CertEnumSystemStoreLocation](CertEnumSystemStoreLocation): enumerasi lokasi certificate store.
- [CertFindChainInStore](CertFindChainInStore): callback pencarian rantai sertifikat di store.

**Loader / modul**

- [EnumerateLoadedModules](EnumerateLoadedModules): enumerasi modul yang dimuat (DbgHelp).
- [EnumerateLoadedModulesEx](EnumerateLoadedModulesEx): varian extended `EnumerateLoadedModules`.
- [LdrEnumerateLoadedModules](LdrEnumerateLoadedModules): enumerasi modul via ntdll loader.
- [LdrpCallInitRoutine](LdrpCallInitRoutine): pemanggilan init routine internal loader (undocumented).
- [VerifierEnumerateResource](VerifierEnumerateResource): enumerasi resource Application Verifier.

**Debug / simbol**

- [SymEnumProcesses](SymEnumProcesses): enumerasi proses untuk resolusi simbol.
- [SymFindFileInPath](SymFindFileInPath): callback pencarian file simbol di search path.
- [FindDebugInfoFileEx](FindDebugInfoFileEx): callback pencarian file debug info (PDB).
- [FindExecutableImageEx](FindExecutableImageEx): callback pencarian image executable untuk simbol.

**Notifikasi jaringan**

- [NotifyIpInterfaceChange](NotifyIpInterfaceChange): callback perubahan antarmuka IP.
- [NotifyRouteChange2](NotifyRouteChange2): callback perubahan tabel routing.
- [NotifyTeredoPortChange](NotifyTeredoPortChange): callback perubahan port Teredo.
- [NotifyUnicastIpAddressChange](NotifyUnicastIpAddressChange): callback perubahan alamat unicast IP.

**Struktur data Comctl (DPA / DSA)**

- [DPA_DestroyCallback](DPA_DestroyCallback): callback destroy elemen dynamic pointer array.
- [DPA_EnumCallback](DPA_EnumCallback): callback enumerasi elemen dynamic pointer array.
- [DSA_DestroyCallback](DSA_DestroyCallback): callback destroy elemen dynamic structure array.
- [DSA_EnumCallback](DSA_EnumCallback): callback enumerasi elemen dynamic structure array.

**Image digest / OCR**

- [ImageGetDigestStream](ImageGetDigestStream): callback stream digest image untuk signing.
- [MappingRecognizeText](MappingRecognizeText): callback pengenalan teks pada image mapping.

**Windows Search (WS)**

- [WsPullBytes](WsPullBytes): callback pull byte stream Windows Search.
- [WsPushBytes](WsPushBytes): callback push byte stream Windows Search.

**Sinkronisasi sekali jalan**

- [InitOnceExecuteOnce](InitOnceExecuteOnce): callback inisialisasi sekali (one-time init).

### Related

- [concealment/stack-spoofing](../../concealment/stack-spoofing): stack spoofing sebelum primitif eksekusi sensitif.
