"use client"

import type React from "react"

import { useState, useEffect, useRef } from "react"
import { useRouter } from "next/navigation"
import { Cloud, X, CheckCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import Link from "next/link"
import { scansAPI } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"
import { useNotifications } from "@/contexts/NotificationContext"

export default function UploadPage() {
  const router = useRouter()
  const { toast } = useToast()
  const { addNotification } = useNotifications()
  const [dragActive, setDragActive] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [appName, setAppName] = useState("")
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [analysisProgress, setAnalysisProgress] = useState(0)
  const [analysisComplete, setAnalysisComplete] = useState(false)
  const [scanId, setScanId] = useState<string | null>(null)
  const [staticAnalysis, setStaticAnalysis] = useState(true)
  const [dynamicAnalysis, setDynamicAnalysis] = useState(false)
  const [fuzzingEnabled, setFuzzingEnabled] = useState(false)
  const [aiAnalysis, setAiAnalysis] = useState(false)
  const [analysisStage, setAnalysisStage] = useState("")
  const [scanResult, setScanResult] = useState<any>(null)
  const [isCancelling, setIsCancelling] = useState(false)
  const pollActiveRef = useRef(false)
  const notifiedSlowScanRef = useRef(false)
  const notifiedScanCompletedRef = useRef(false)

  // Load ongoing scan from localStorage on mount
  useEffect(() => {
    const savedScan = localStorage.getItem('ongoing_scan')
    const currentUser = localStorage.getItem('user_id') // Get current user ID
    
    if (savedScan) {
      const { scanId: savedId, appName: savedAppName, userId } = JSON.parse(savedScan)
      
      const isCurrentUser = userId === currentUser
      if (isCurrentUser) {
        setScanId(savedId)
        setAppName(savedAppName)
        setIsAnalyzing(true)
        setAnalysisStage("Resuming analysis...")
        pollScanStatus(savedId)
      } else {
        // Clean up old or different user's scan
        localStorage.removeItem('ongoing_scan')
      }
    }
  }, [])

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true)
    } else if (e.type === "dragleave") {
      setDragActive(false)
    }
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const droppedFile = e.dataTransfer.files[0]
      if (droppedFile.name.endsWith(".apk")) {
        setFile(droppedFile)
        // Auto-fill app name from filename if empty
        if (!appName) {
          const filename = droppedFile.name.replace('.apk', '')
          setAppName(filename)
        }
      } else {
        toast({ title: "Invalid File", description: "Please upload a valid APK file", variant: "destructive" })
      }
    }
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selectedFile = e.target.files[0]
      if (selectedFile.name.endsWith('.apk')) {
        setFile(selectedFile)
        // Auto-fill app name from filename if empty
        if (!appName) {
          const filename = selectedFile.name.replace('.apk', '')
          setAppName(filename)
        }
      } else {
        toast({ title: "Invalid File", description: "Please select a valid APK file", variant: "destructive" })
      }
    }
  }

  const handleStartAnalysis = async () => {
    if (!file) {
      toast({ title: "Error", description: "Please provide APK file", variant: "destructive" })
      return
    }
    
    // Use filename if app name is empty
    const finalAppName = appName.trim() || file.name.replace('.apk', '')

    notifiedSlowScanRef.current = false
    notifiedScanCompletedRef.current = false
    
    setIsAnalyzing(true)
    setAnalysisProgress(10)
    setAnalysisStage("Uploading APK...")
    
    try {
      const response = await scansAPI.create(file, finalAppName, "", {
        staticAnalysis,
        dynamicAnalysis,
        fuzzingEnabled,
        aiAnalysis,
      })
      
      // Check if this is an existing scan
      if (response.data.existing) {
        const existingScan = response.data.scan
        toast({ 
          title: "APK Already Scanned", 
          description: `This APK has already been analyzed. Threat Level: ${existingScan.threat_level}`,
        })
        setScanId(existingScan.id)
        
        // If still scanning, poll status
        if (existingScan.status !== 'completed') {
          pollScanStatus(existingScan.id)
        } else {
          // Already completed, show results
          setIsAnalyzing(false)
          setAnalysisProgress(100)
          setAnalysisStage("Analysis completed!")
          router.push(`/dashboard/reports/${existingScan.id}`)
        }
        return
      }
      
      const newScanId = response.data.id
      setScanId(newScanId)
      setAnalysisProgress(20)
      setAnalysisStage("Decompiling APK...")
      
      // Add notification for upload start
      addNotification({
        title: 'Scan Started',
        message: `Analysis started for "${appName}". This may take a few moments.`,
        type: 'info'
      })
      
      // Save to localStorage for persistence
      const currentUser = localStorage.getItem('user_id')
      localStorage.setItem('ongoing_scan', JSON.stringify({
        scanId: newScanId,
        appName,
        timestamp: Date.now(),
        userId: currentUser
      }))
      
      // Start polling scan status
      pollScanStatus(newScanId)
    } catch (error: any) {
      toast({ title: "Error", description: error.response?.data?.error || "Failed to upload APK", variant: "destructive" })
      
      // Add notification for upload error
      addNotification({
        title: 'Upload Failed',
        message: error.response?.data?.error || "Failed to upload APK. Please try again.",
        type: 'error'
      })
      
      setIsAnalyzing(false)
      setAnalysisProgress(0)
    }
  }

  const handleCancelScan = async () => {
    if (!scanId || isCancelling) return

    try {
      setIsCancelling(true)
      pollActiveRef.current = false
      await scansAPI.cancelScan(scanId)

      localStorage.removeItem('ongoing_scan')
      setIsAnalyzing(false)
      setAnalysisProgress(0)
      setAnalysisStage("Analysis cancelled")
      setScanId(null)

      toast({ title: "Scan Cancelled", description: "The running scan was cancelled successfully." })
      addNotification({
        title: 'Scan Cancelled',
        message: 'The running analysis has been cancelled.',
        type: 'info'
      })
    } catch (error: any) {
      toast({
        title: "Cancel Failed",
        description: error.response?.data?.error || "Unable to cancel scan right now.",
        variant: "destructive"
      })
    } finally {
      setIsCancelling(false)
    }
  }

  const pollScanStatus = async (id: string) => {
    pollActiveRef.current = true
    let attempts = 0
    
    const checkStatus = async () => {
      if (!pollActiveRef.current) return

      try {
        const response = await scansAPI.get(id)
        const scan = response.data

        if (!notifiedSlowScanRef.current && attempts >= 25) {
          notifiedSlowScanRef.current = true
          addNotification({
            title: 'Scan In Progress',
            message: 'Scan is taking more time than expected. Report will be available once the scan is completed.',
            type: 'warning',
          })
        }
        
        if (scan.status === 'completed') {
          setAnalysisProgress(100)
          setAnalysisStage("Analysis complete!")
          setScanResult(scan)
          localStorage.removeItem('ongoing_scan') // Clear saved state
          
          if (!notifiedScanCompletedRef.current) {
            notifiedScanCompletedRef.current = true
            addNotification({
              title: 'Scan Completed',
              message: 'Scan is completed. You can go and check the results.',
              type: 'success',
              action: {
                label: 'View Results',
                href: `/dashboard/reports/${scan.id}`,
              },
            })
          }
          
          setTimeout(() => {
            setAnalysisComplete(true)
          }, 500)
          pollActiveRef.current = false
          return
        } else if (scan.status === 'failed') {
          if ((scan.error_message || '').toLowerCase().includes('cancelled')) {
            pollActiveRef.current = false
            localStorage.removeItem('ongoing_scan')
            setIsAnalyzing(false)
            setAnalysisProgress(0)
            setAnalysisStage("Analysis cancelled")
            return
          }

          toast({ 
            title: "Analysis Failed", 
            description: scan.error_message || "An error occurred during analysis. Retrying...",
            variant: "destructive" 
          })
          
          // Add notification for scan failure
          addNotification({
            title: 'Analysis Failed',
            message: scan.error_message || "An error occurred during analysis. The system will retry automatically.",
            type: 'error'
          })
          
          // Auto-retry failed scan
          setAnalysisStage("Retrying analysis...")
          try {
            await scansAPI.rescan(id)
            // Continue polling
            if (pollActiveRef.current) setTimeout(checkStatus, 3000)
          } catch (retryError) {
            console.error('Retry failed:', retryError)
            setIsAnalyzing(false)
            setAnalysisProgress(0)
            localStorage.removeItem('ongoing_scan')
            pollActiveRef.current = false
          }
          return
        } else if (scan.status === 'scanning') {
          // Update progress based on time elapsed
          const progress = Math.min(90, 20 + (attempts * 3))
          setAnalysisProgress(progress)
          
          // Update stage based on progress
          if (progress < 40) {
            setAnalysisStage("Extracting APK contents...")
          } else if (progress < 60) {
            setAnalysisStage("Analyzing code for vulnerabilities...")
          } else if (progress < 80) {
            setAnalysisStage("Running security checks...")
          } else {
            setAnalysisStage("Generating report...")
          }
        }
        
        // Continue polling until the scan finishes or the user cancels it
        attempts++
        if (pollActiveRef.current) setTimeout(checkStatus, 2000) // Check every 2 seconds
      } catch (error: any) {
        console.error('Failed to check scan status:', error)
        
        // Handle 404 errors (scan doesn't exist or belongs to different user)
        if (error.response?.status === 404) {
          localStorage.removeItem('ongoing_scan') // Clear invalid scan
          setIsAnalyzing(false)
          setAnalysisProgress(0)
          pollActiveRef.current = false
          toast({ 
            title: "Scan Not Found", 
            description: "The scan is no longer available. Please start a new analysis.",
            variant: "destructive" 
          })
          return
        }
        
        attempts++
        if (pollActiveRef.current) setTimeout(checkStatus, 2000)
      }
    }
    
    checkStatus()
  }

  return (
    <div className="max-w-3xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Upload APK for Analysis</h1>
        <p className="text-slate-400 mt-2">Analyze security vulnerabilities in your Android applications</p>
      </div>

      {!analysisComplete ? (
        <div className="space-y-6">
          {/* Upload Zone */}
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            className={`glassmorphism border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition ${
              dragActive ? "border-cyan-400 bg-cyan-500/5" : "border-slate-600 hover:border-cyan-500"
            }`}
          >
            {!file ? (
              <>
                <Cloud className="w-16 h-16 text-cyan-400 mx-auto mb-4" />
                <p className="text-white font-semibold mb-2">Drag and drop your APK file here</p>
                <p className="text-slate-400 text-sm mb-6">or</p>
                <label>
                  <input type="file" accept=".apk" onChange={handleFileSelect} className="hidden" />
                  <span className="inline-block px-6 py-2 bg-cyan-500 hover:bg-cyan-600 text-slate-950 font-semibold rounded-lg transition cursor-pointer">
                    Browse Files
                  </span>
                </label>
                <p className="text-slate-500 text-xs mt-6">Maximum file size: 100MB | Supported: .apk</p>
              </>
            ) : (
              <>
                <div className="bg-slate-800 p-4 rounded-lg inline-block mb-4">
                  <span className="text-4xl">📦</span>
                </div>
                <p className="text-white font-semibold">{file.name}</p>
                <p className="text-slate-400 text-sm mt-1">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                <button
                  onClick={() => setFile(null)}
                  className="mt-4 inline-flex items-center gap-2 px-4 py-2 text-red-400 hover:bg-red-500/10 rounded-lg transition cursor-pointer"
                >
                  <X className="w-4 h-4" />
                  Remove
                </button>
              </>
            )}
          </div>

          {file && !isAnalyzing && (
            <>
              {/* APK Details */}
              <div className="glassmorphism p-6 rounded-lg cyber-border space-y-4">
                <h3 className="text-white font-semibold mb-4">APK Details</h3>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">App Name <span className="text-slate-500">(Optional)</span></label>
                  <input
                    type="text"
                    placeholder={file ? file.name.replace('.apk', '') : "e.g., MyApp"}
                    value={appName}
                    onChange={(e) => setAppName(e.target.value)}
                    autoComplete="off"
                    className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 cursor-text"
                  />
                  <p className="text-slate-400 text-xs mt-2">Leave empty to use filename. Package name will be auto-detected from APK.</p>
                </div>
              </div>

              {/* Analysis Options */}
              <div className="glassmorphism p-6 rounded-lg cyber-border space-y-4">
                <h3 className="text-white font-semibold">Analysis Options</h3>

                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={staticAnalysis}
                    onChange={(e) => setStaticAnalysis(e.target.checked)}
                    className="w-5 h-5 rounded bg-slate-800 border-slate-700 text-cyan-500 cursor-pointer"
                  />
                  <div>
                    <p className="text-white font-medium">Static Analysis</p>
                    <p className="text-slate-400 text-sm">Analyze code structure and permissions</p>
                  </div>
                </label>

                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={dynamicAnalysis}
                    onChange={(e) => setDynamicAnalysis(e.target.checked)}
                    className="w-5 h-5 rounded bg-slate-800 border-slate-700 text-cyan-500 cursor-pointer"
                  />
                  <div>
                    <p className="text-white font-medium">Dynamic Analysis</p>
                    <p className="text-slate-400 text-sm">Run and monitor APK behavior</p>
                  </div>
                </label>

                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={aiAnalysis}
                    onChange={(e) => setAiAnalysis(e.target.checked)}
                    className="w-5 h-5 rounded bg-slate-800 border-slate-700 text-violet-500 cursor-pointer"
                  />
                  <div className="flex-1">
                    <p className="text-white font-medium">AI Security Analysis</p>
                    <p className="text-slate-400 text-sm mt-0.5">MITRE ATT&amp;CK mapping, threat intelligence profiling, severity re-scoring, and remediation roadmap</p>
                  </div>
                </label>

                <label className="flex items-center gap-3 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={fuzzingEnabled}
                    onChange={(e) => setFuzzingEnabled(e.target.checked)}
                    className="w-5 h-5 rounded bg-slate-800 border-slate-700 text-orange-500 cursor-pointer"
                  />
                  <div className="flex-1">
                    <p className="text-white font-medium">Component Security Fuzzing</p>
                    <p className="text-slate-400 text-sm mt-0.5">Probe exported Activities, Services, Receivers &amp; Content Providers for Intent injection, SQL injection, and crash vulnerabilities</p>
                  </div>
                </label>

              </div>

              {/* Action Buttons */}
              <div className="flex gap-4">
                <Button
                  onClick={handleStartAnalysis}
                  className="flex-1 bg-gradient-to-r from-cyan-500 to-cyan-600 hover:from-cyan-600 hover:to-cyan-700 text-slate-950 font-semibold py-3 rounded-lg transition cyber-glow-hover cursor-pointer"
                >
                  Start Analysis
                </Button>
                <Button
                  variant="outline"
                  onClick={() => setFile(null)}
                  className="px-6 border-slate-600 text-slate-300 hover:bg-slate-800 cursor-pointer"
                >
                  Cancel
                </Button>
              </div>
            </>
          )}

          {isAnalyzing && (
            <div className="glassmorphism p-8 rounded-lg cyber-border text-center">
              <div className="inline-block p-4 bg-cyan-500/20 rounded-full mb-4">
                <div className="animate-spin">
                  <span className="text-4xl">🔍</span>
                </div>
              </div>
              <p className="text-white font-semibold mb-2">{analysisStage || "Analyzing APK..."}</p>
              <p className="text-slate-400 text-sm mb-6">This may take a few minutes</p>

              <div className="w-full bg-slate-800 rounded-full h-3 overflow-hidden mb-4">
                <div
                  className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-cyan-400 transition-all duration-500"
                  style={{ width: `${analysisProgress}%` }}
                />
              </div>
              <p className="text-cyan-400 font-semibold text-lg">{Math.round(analysisProgress)}%</p>
              
              <div className="mt-6 text-left bg-slate-800/30 p-4 rounded-lg">
                <p className="text-slate-400 text-sm mb-2">Analysis Steps:</p>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${analysisProgress > 10 ? 'bg-green-400' : 'bg-slate-600'}`} />
                    <span className="text-slate-300 text-sm">APK Upload & Extraction</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${analysisProgress > 30 ? 'bg-green-400' : 'bg-slate-600'}`} />
                    <span className="text-slate-300 text-sm">Decompiling Code</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${analysisProgress > 50 ? 'bg-green-400' : 'bg-slate-600'}`} />
                    <span className="text-slate-300 text-sm">Vulnerability Scanning</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${analysisProgress > 70 ? 'bg-green-400' : 'bg-slate-600'}`} />
                    <span className="text-slate-300 text-sm">Security Checks</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${analysisProgress > 90 ? 'bg-green-400' : 'bg-slate-600'}`} />
                    <span className="text-slate-300 text-sm">Report Generation</span>
                  </div>
                </div>
              </div>

              <div className="mt-6">
                <Button
                  onClick={handleCancelScan}
                  disabled={!scanId || isCancelling}
                  variant="outline"
                  className="border-red-500/60 text-red-300 hover:bg-red-500/10 cursor-pointer"
                >
                  {isCancelling ? "Cancelling..." : "Cancel Scan"}
                </Button>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="glassmorphism p-12 rounded-lg cyber-border text-center">
          <div className="inline-block p-4 bg-green-500/20 rounded-full mb-4">
            <CheckCircle className="w-12 h-12 text-green-400" />
          </div>
          <p className="text-white font-semibold text-xl mb-2">Analysis Complete!</p>
          <p className="text-slate-400 mb-6">Your APK has been successfully analyzed</p>

          <div className="grid grid-cols-3 gap-4 mb-8 text-left">
            <div className="bg-slate-800/50 p-4 rounded-lg">
              <p className="text-slate-400 text-sm">Vulnerabilities</p>
              <p className="text-cyan-400 text-2xl font-bold mt-1">{scanResult?.total_issues || 0}</p>
            </div>
            <div className="bg-slate-800/50 p-4 rounded-lg">
              <p className="text-slate-400 text-sm">Risk Score</p>
              <p className={`text-2xl font-bold mt-1 ${
                scanResult?.threat_level === 'critical' ? 'text-red-400' :
                scanResult?.threat_level === 'high' ? 'text-orange-400' :
                scanResult?.threat_level === 'medium' ? 'text-yellow-400' :
                'text-green-400'
              }`}>{scanResult?.threat_score || 0}</p>
            </div>
            <div className="bg-slate-800/50 p-4 rounded-lg">
              <p className="text-slate-400 text-sm">Threat Level</p>
              <p className={`text-lg font-bold mt-1 capitalize ${
                scanResult?.threat_level === 'critical' ? 'text-red-400' :
                scanResult?.threat_level === 'high' ? 'text-orange-400' :
                scanResult?.threat_level === 'medium' ? 'text-yellow-400' :
                'text-green-400'
              }`}>{scanResult?.threat_level || 'safe'}</p>
            </div>
          </div>

          <div className="flex gap-4 justify-center">
            <Link href={scanId ? `/dashboard/reports/${scanId}` : "/dashboard/reports"}>
              <Button className="bg-gradient-to-r from-cyan-500 to-cyan-600 hover:from-cyan-600 hover:to-cyan-700 text-slate-950 font-semibold cyber-glow-hover">
                View Report
              </Button>
            </Link>
            <Button
              onClick={() => {
                setFile(null)
                setAppName("")
                setAnalysisComplete(false)
                setAnalysisProgress(0)
                setScanId(null)
                setScanResult(null)
                setAnalysisStage("")
              }}
              variant="outline"
              className="border-slate-600 text-slate-300 hover:bg-slate-800"
            >
              Upload Another
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
