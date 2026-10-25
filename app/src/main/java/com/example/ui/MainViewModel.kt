package com.example.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.local.AppDatabase
import com.example.data.local.QuarantineEntity
import com.example.data.local.ScanReportEntity
import com.example.data.local.SecurityAlertEntity
import com.example.data.repository.SecurityRepository
import com.example.data.repository.ShieldSettingsState
import com.example.domain.audio.SoundPlayer
import com.example.domain.scanner.NetworkSecurityReport
import com.example.domain.scanner.NetworkShieldEngine
import com.example.domain.scanner.PrivacyAuditReport
import com.example.domain.scanner.PrivacyEngine
import com.example.domain.scanner.ScanMode
import com.example.domain.scanner.ScanProgressState
import com.example.domain.scanner.SystemHealthReport
import com.example.domain.scanner.SystemOptimizer
import com.example.domain.scanner.VirusScannerEngine
import com.example.domain.scanner.WebCheckResult
import com.example.domain.scanner.WebShieldEngine
import com.example.ui.components.ShieldStatus
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

enum class ScreenNav(val title: String) {
    DASHBOARD("Dashboard"),
    ANTIVIRUS("Antivirus"),
    WEB_SHIELD("Web Shield"),
    NETWORK("Network"),
    PRIVACY("Privacy"),
    SYSTEM("System Health"),
    REPORTS("Reports"),
    SETTINGS("Settings"),
    ABOUT("About DTZ")
}

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val db = AppDatabase.getInstance(application)
    val repository = SecurityRepository(db)

    val soundPlayer = SoundPlayer(viewModelScope)
    private val virusScanner = VirusScannerEngine(application)
    private val webShieldEngine = WebShieldEngine()
    private val networkEngine = NetworkShieldEngine(application)
    private val privacyEngine = PrivacyEngine(application)
    private val systemOptimizer = SystemOptimizer(application)

    private val _currentScreen = MutableStateFlow(ScreenNav.DASHBOARD)
    val currentScreen = _currentScreen.asStateFlow()

    val settings: StateFlow<ShieldSettingsState> = repository.settings

    val quarantinedItems: StateFlow<List<QuarantineEntity>> = repository.quarantinedItems
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val scanReports: StateFlow<List<ScanReportEntity>> = repository.scanReports
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val alerts: StateFlow<List<SecurityAlertEntity>> = repository.alerts
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _scanProgress = MutableStateFlow(ScanProgressState())
    val scanProgress = _scanProgress.asStateFlow()

    private val _isScanning = MutableStateFlow(false)
    val isScanning = _isScanning.asStateFlow()

    private val _activeScanMode = MutableStateFlow(ScanMode.SMART)
    val activeScanMode = _activeScanMode.asStateFlow()

    private val _shieldStatus = MutableStateFlow(ShieldStatus.PROTECTED)
    val shieldStatus = _shieldStatus.asStateFlow()

    private val _networkReport = MutableStateFlow<NetworkSecurityReport?>(null)
    val networkReport = _networkReport.asStateFlow()

    private val _privacyReport = MutableStateFlow<PrivacyAuditReport?>(null)
    val privacyReport = _privacyReport.asStateFlow()

    private val _systemHealth = MutableStateFlow<SystemHealthReport?>(null)
    val systemHealth = _systemHealth.asStateFlow()

    private val _webCheckResult = MutableStateFlow<WebCheckResult?>(null)
    val webCheckResult = _webCheckResult.asStateFlow()

    private val _blockedSiteWarning = MutableStateFlow<WebCheckResult?>(null)
    val blockedSiteWarning = _blockedSiteWarning.asStateFlow()

    private var scanJob: Job? = null

    // Dynamic security score derived from shield status & alerts
    val securityScore: StateFlow<Int> = combine(
        alerts,
        quarantinedItems,
        settings
    ) { alertList, quarantineList, _ ->
        val unresolved = alertList.count { !it.isResolved }
        repository.calculateSecurityScore(unresolved, quarantineList.size)
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 94)

    init {
        soundPlayer.isSoundEnabled = settings.value.soundEffects
        runNetworkScan()
        runPrivacyAudit()
        runSystemDiagnostics()
    }

    fun navigateTo(screen: ScreenNav) {
        soundPlayer.playClick()
        _currentScreen.value = screen
    }

    fun startScan(mode: ScanMode) {
        if (_isScanning.value) return
        _activeScanMode.value = mode
        _isScanning.value = true
        _shieldStatus.value = ShieldStatus.SCANNING
        soundPlayer.playScanStart()

        val startTime = System.currentTimeMillis()

        scanJob = viewModelScope.launch {
            try {
                virusScanner.executeScan(mode).collect { progress ->
                    _scanProgress.value = progress

                    if (progress.threatsFound.isNotEmpty() && _shieldStatus.value != ShieldStatus.THREAT_DETECTED) {
                        _shieldStatus.value = ShieldStatus.THREAT_DETECTED
                        soundPlayer.playThreatAlert()
                    }

                    if (progress.isFinished) {
                        _isScanning.value = false
                        for (threat in progress.threatsFound) {
                            repository.quarantineThreat(threat)
                        }

                        val report = ScanReportEntity(
                            scanType = mode.title,
                            startTime = startTime,
                            endTime = System.currentTimeMillis(),
                            itemsChecked = progress.itemsScanned,
                            threatsFound = progress.threatsFound.size,
                            threatsQuarantined = progress.threatsFound.size,
                            result = if (progress.threatsFound.isEmpty()) "Clean" else "Threats Resolved"
                        )
                        repository.saveScanReport(report)

                        if (progress.threatsFound.isEmpty()) {
                            _shieldStatus.value = ShieldStatus.PROTECTED
                            soundPlayer.playScanComplete()
                        } else {
                            _shieldStatus.value = ShieldStatus.THREAT_DETECTED
                        }
                    }
                }
            } catch (_: Exception) {
                _isScanning.value = false
                _shieldStatus.value = ShieldStatus.PROTECTED
            }
        }
    }

    fun cancelScan() {
        scanJob?.cancel()
        _isScanning.value = false
        _shieldStatus.value = ShieldStatus.PROTECTED
        soundPlayer.playClick()
    }

    fun checkUrl(url: String) {
        soundPlayer.playClick()
        val result = webShieldEngine.evaluateUrl(url)
        _webCheckResult.value = result
        if (result.isBlocked) {
            soundPlayer.playThreatAlert()
            _blockedSiteWarning.value = result
            viewModelScope.launch {
                repository.logAlert(
                    SecurityAlertEntity(
                        title = "Malicious URL Blocked: ${result.domain}",
                        description = result.reason,
                        severity = result.riskLevel,
                        source = "Web Shield",
                        recommendedAction = result.recommendedAction
                    )
                )
            }
        }
    }

    fun dismissBlockedWarning() {
        _blockedSiteWarning.value = null
    }

    fun runNetworkScan() {
        viewModelScope.launch {
            val report = networkEngine.analyzeNetwork()
            _networkReport.value = report
        }
    }

    fun runPrivacyAudit() {
        viewModelScope.launch {
            val s = settings.value
            val report = privacyEngine.auditPrivacy(s.ransomwareProtection, s.webcamProtection)
            _privacyReport.value = report
        }
    }

    fun runSystemDiagnostics() {
        viewModelScope.launch {
            val report = systemOptimizer.getHealthReport()
            _systemHealth.value = report
        }
    }

    fun optimizeCache() {
        soundPlayer.playScanComplete()
        systemOptimizer.optimizeCache()
        runSystemDiagnostics()
        viewModelScope.launch {
            repository.logAlert(
                SecurityAlertEntity(
                    title = "System Storage Cleaned",
                    description = "Transient junk files and cache memory purged successfully.",
                    severity = "Safe",
                    source = "System Health",
                    isResolved = true
                )
            )
        }
    }

    fun restoreQuarantineItem(item: QuarantineEntity) {
        soundPlayer.playClick()
        viewModelScope.launch {
            repository.restoreQuarantinedItem(item)
            if (quarantinedItems.value.isEmpty()) {
                _shieldStatus.value = ShieldStatus.PROTECTED
            }
        }
    }

    fun deleteQuarantineItem(item: QuarantineEntity) {
        soundPlayer.playClick()
        viewModelScope.launch {
            repository.permanentlyDeleteQuarantinedItem(item)
            if (quarantinedItems.value.isEmpty()) {
                _shieldStatus.value = ShieldStatus.PROTECTED
            }
        }
    }

    fun clearAllQuarantine() {
        soundPlayer.playClick()
        viewModelScope.launch {
            repository.clearQuarantine()
            _shieldStatus.value = ShieldStatus.PROTECTED
        }
    }

    fun resolveAlert(alertId: Long) {
        soundPlayer.playClick()
        viewModelScope.launch {
            repository.resolveAlert(alertId)
        }
    }

    fun resolveAllAlerts() {
        soundPlayer.playClick()
        viewModelScope.launch {
            repository.resolveAllAlerts()
            _shieldStatus.value = ShieldStatus.PROTECTED
        }
    }

    fun fixAllIssues() {
        soundPlayer.playScanComplete()
        viewModelScope.launch {
            repository.fixAllIssues()
            _shieldStatus.value = ShieldStatus.RESOLVED
            runPrivacyAudit()
            runNetworkScan()
            runSystemDiagnostics()
        }
    }

    fun updateDefinitions() {
        soundPlayer.playScanComplete()
        viewModelScope.launch {
            repository.updateDefinitions()
        }
    }

    fun triggerSafeDemo() {
        soundPlayer.playThreatAlert()
        _shieldStatus.value = ShieldStatus.THREAT_DETECTED
        viewModelScope.launch {
            repository.triggerSafeDemo()
        }
    }

    fun toggleRealTime(enabled: Boolean) {
        soundPlayer.playShieldToggled(enabled)
        repository.toggleRealTime(enabled)
    }

    fun toggleWebShield(enabled: Boolean) {
        soundPlayer.playShieldToggled(enabled)
        repository.toggleWebShield(enabled)
    }

    fun toggleNetworkShield(enabled: Boolean) {
        soundPlayer.playShieldToggled(enabled)
        repository.toggleNetworkShield(enabled)
    }

    fun toggleRansomware(enabled: Boolean) {
        soundPlayer.playShieldToggled(enabled)
        repository.toggleRansomware(enabled)
        runPrivacyAudit()
    }

    fun toggleWebcam(enabled: Boolean) {
        soundPlayer.playShieldToggled(enabled)
        repository.toggleWebcam(enabled)
        runPrivacyAudit()
    }

    fun toggleGameMode(enabled: Boolean) {
        soundPlayer.playShieldToggled(enabled)
        repository.toggleGameMode(enabled)
    }

    fun togglePerformanceMode(enabled: Boolean) {
        soundPlayer.playClick()
        repository.togglePerformanceMode(enabled)
    }

    fun toggleSound(enabled: Boolean) {
        repository.toggleSound(enabled)
        soundPlayer.isSoundEnabled = enabled
    }
}
