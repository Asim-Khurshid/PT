"use client"

import { useState, useEffect } from "react"
import { Search, Filter, Download, Eye, Trash2, AlertTriangle } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import Link from "next/link"
import { scansAPI } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"
import { useNotifications } from "@/contexts/NotificationContext"

export default function ReportsPage() {
  const { toast } = useToast()
  const { addNotification } = useNotifications()
  const [searchTerm, setSearchTerm] = useState("")
  const [filterSeverity, setFilterSeverity] = useState("all")
  const [reports, setReports] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [downloadingId, setDownloadingId] = useState<string | null>(null)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [deleteDialog, setDeleteDialog] = useState<{open: boolean, reportId: string, appName: string}>({ open: false, reportId: '', appName: '' })

  const fetchReports = () => {
    setLoading(true)
    scansAPI.list()
      .then(res => {
        setReports(res.data.results || res.data || [])
        setLoading(false)
      })
      .catch(err => {
        console.error('Failed to fetch reports:', err)
        toast({ title: "Error", description: "Failed to load reports", variant: "destructive" })
        setLoading(false)
      })
  }

  useEffect(() => {
    fetchReports()
  }, [])

  const filteredReports = reports.filter((report) => {
    const matchesSearch =
      report.app_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      report.package_name?.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesFilter = filterSeverity === "all" || report.threat_level?.toLowerCase() === filterSeverity.toLowerCase()
    return matchesSearch && matchesFilter
  })

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical":
        return "bg-red-500/20 text-red-400 border-red-500/30"
      case "High":
        return "bg-orange-500/20 text-orange-400 border-orange-500/30"
      case "Medium":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
      case "Low":
        return "bg-blue-500/20 text-blue-400 border-blue-500/30"
      case "Safe":
        return "bg-green-500/20 text-green-400 border-green-500/30"
      default:
        return "bg-slate-500/20 text-slate-400 border-slate-500/30"
    }
  }

  const getRiskScoreColor = (score: number) => {
    if (score >= 70) return "text-red-400"
    if (score >= 50) return "text-orange-400"
    if (score >= 30) return "text-yellow-400"
    return "text-green-400"
  }

  const handleDownloadPDF = async (reportId: string, appName: string) => {
    if (downloadingId) return // Prevent multiple simultaneous downloads
    
    setDownloadingId(reportId)
    try {
      const response = await scansAPI.downloadPDF(reportId)
      
      // Create blob from response
      const blob = new Blob([response.data], { type: 'application/pdf' })
      const url = window.URL.createObjectURL(blob)
      
      // Create temporary link and trigger download
      const link = document.createElement('a')
      link.href = url
      link.download = `${appName}_security_report.pdf`
      document.body.appendChild(link)
      link.click()
      
      // Cleanup
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
      
      toast({ 
        title: "Success", 
        description: "PDF report downloaded successfully",
      })
      
      // Add notification for successful download
      addNotification({
        title: 'PDF Downloaded',
        message: `Security report for "${appName}" downloaded successfully`,
        type: 'success'
      })
    } catch (error: any) {
      console.error('Download failed:', error)
      toast({ 
        title: "Download Failed", 
        description: error.response?.data?.error || "Failed to download PDF report",
        variant: "destructive" 
      })
    } finally {
      setDownloadingId(null)
    }
  }

  const openDeleteDialog = (reportId: string, appName: string) => {
    setDeleteDialog({ open: true, reportId, appName })
  }

  const handleDeleteScan = async () => {
    if (deletingId) return // Prevent multiple simultaneous deletes
    
    const { reportId, appName } = deleteDialog
    setDeleteDialog({ open: false, reportId: '', appName: '' })
    setDeletingId(reportId)
    
    try {
      await scansAPI.delete(reportId)
      
      // Show success toast
      toast({ 
        title: "✓ Scan Deleted", 
        description: `Successfully removed "${appName}" from your reports`,
        className: "bg-green-500/10 border-green-500/50 text-white"
      })
      
      // Add notification
      addNotification({
        title: 'Scan Deleted',
        message: `Removed security scan for "${appName}"`,
        type: 'success'
      })
      
      // Refresh the reports list
      fetchReports()
    } catch (error: any) {
      console.error('Delete failed:', error)
      toast({ 
        title: "⚠ Delete Failed", 
        description: error.response?.data?.error || "Unable to delete scan. Please try again.",
        variant: "destructive" 
      })
      
      addNotification({
        title: 'Delete Failed',
        message: `Could not delete scan for "${appName}"`,
        type: 'error'
      })
    } finally {
      setDeletingId(null)
    }
  }

  return (
    <div className="max-w-6xl">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Security Reports</h1>
        <p className="text-slate-400 mt-2">View and manage all APK security analysis reports</p>
      </div>

      {/* Filters and Search */}
      <div className="flex gap-4 mb-6">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-3 w-5 h-5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by app name or package..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            autoComplete="off"
            className="w-full pl-10 pr-4 py-2.5 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50 transition cursor-text"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-5 h-5 text-slate-400" />
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="px-4 py-2.5 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50 transition cursor-pointer"
          >
            <option value="all">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Safe">Safe</option>
          </select>
        </div>
      </div>

      {/* Reports Table */}
      <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-800/50 border-b border-slate-700">
              <tr>
                <th className="px-6 py-4 text-left text-sm font-semibold text-slate-300">App Name</th>
                <th className="px-6 py-4 text-left text-sm font-semibold text-slate-300">Package</th>
                <th className="px-6 py-4 text-left text-sm font-semibold text-slate-300">Risk Score</th>
                <th className="px-6 py-4 text-left text-sm font-semibold text-slate-300">Severity</th>
                <th className="px-6 py-4 text-left text-sm font-semibold text-slate-300">Issues</th>
                <th className="px-6 py-4 text-left text-sm font-semibold text-slate-300">Date</th>
                <th className="px-6 py-4 text-left text-sm font-semibold text-slate-300">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-6 py-8 text-center text-slate-400">
                    Loading reports...
                  </td>
                </tr>
              ) : filteredReports.length > 0 ? (
                filteredReports.map((report) => (
                  <tr key={report.id} className="hover:bg-slate-800/30 transition">
                    <td className="px-6 py-4 text-white font-medium">{report.app_name}</td>
                    <td className="px-6 py-4 text-slate-400 text-sm font-mono">{report.package_name}</td>
                    <td className="px-6 py-4">
                      <span className={`font-bold text-lg ${getRiskScoreColor(report.threat_score || 0)}`}>
                        {report.threat_score || 0}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={`px-3 py-1 rounded-full text-xs font-semibold border capitalize ${getSeverityColor(report.threat_level || 'safe')}`}
                      >
                        {report.threat_level || 'Safe'}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-cyan-400 font-medium">{report.total_issues || 0} found</span>
                    </td>
                    <td className="px-6 py-4 text-slate-400 text-sm">{new Date(report.created_at).toLocaleDateString()}</td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <Link href={`/dashboard/reports/${report.id}`}>
                          <Button
                            size="sm"
                            className="bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 p-2 h-auto cursor-pointer"
                            title="View Report"
                          >
                            <Eye className="w-4 h-4" />
                          </Button>
                        </Link>
                        <Button
                          size="sm"
                          onClick={() => handleDownloadPDF(report.id, report.app_name)}
                          disabled={downloadingId === report.id || report.status !== 'completed'}
                          className="bg-slate-500/10 hover:bg-slate-500/20 text-slate-400 border border-slate-500/30 p-2 h-auto cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                          title="Download PDF Report"
                        >
                          {downloadingId === report.id ? (
                            <div className="w-4 h-4 border-2 border-slate-400 border-t-transparent rounded-full animate-spin" />
                          ) : (
                            <Download className="w-4 h-4" />
                          )}
                        </Button>
                        <Button
                          size="sm"
                          onClick={() => openDeleteDialog(report.id, report.app_name)}
                          disabled={deletingId === report.id}
                          className="bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 p-2 h-auto cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                          title="Delete Scan"
                        >
                          {deletingId === report.id ? (
                            <div className="w-4 h-4 border-2 border-red-400 border-t-transparent rounded-full animate-spin" />
                          ) : (
                            <Trash2 className="w-4 h-4" />
                          )}
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="px-6 py-8 text-center text-slate-400">
                    No reports found matching your criteria
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-4 gap-4 mt-6">
        <div className="glassmorphism p-4 rounded-lg cyber-border text-center">
          <p className="text-slate-400 text-xs">Total Reports</p>
          <p className="text-2xl font-bold text-cyan-400 mt-1">{reports.length}</p>
        </div>
        <div className="glassmorphism p-4 rounded-lg cyber-border text-center">
          <p className="text-slate-400 text-xs">Critical Issues</p>
          <p className="text-2xl font-bold text-red-400 mt-1">
            {reports.filter((r) => r.threat_level === "critical").length}
          </p>
        </div>
        <div className="glassmorphism p-4 rounded-lg cyber-border text-center">
          <p className="text-slate-400 text-xs">Average Risk</p>
          <p className="text-2xl font-bold text-orange-400 mt-1">
            {reports.length > 0 ? Math.round(reports.reduce((a, b) => a + (b.threat_score || 0), 0) / reports.length) : 0}
          </p>
        </div>
        <div className="glassmorphism p-4 rounded-lg cyber-border text-center">
          <p className="text-slate-400 text-xs">Safe Apps</p>
          <p className="text-2xl font-bold text-green-400 mt-1">
            {reports.filter((r) => r.threat_level === "safe" || r.threat_level === "low").length}
          </p>
        </div>
      </div>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteDialog.open} onOpenChange={(open) => setDeleteDialog({ ...deleteDialog, open })}>
        <AlertDialogContent className="glassmorphism border-slate-700">
          <AlertDialogHeader>
            <div className="flex items-center gap-3 mb-2">
              <div className="p-3 rounded-full bg-red-500/10 border border-red-500/30">
                <AlertTriangle className="w-6 h-6 text-red-400" />
              </div>
              <AlertDialogTitle className="text-white text-xl">Delete Security Scan</AlertDialogTitle>
            </div>
            <AlertDialogDescription className="text-slate-300 text-base mt-3">
              Are you sure you want to delete the security scan for <span className="font-semibold text-white">"{deleteDialog.appName}"</span>?
              <br />
              <span className="text-slate-400 text-sm mt-2 block">This action cannot be undone. All vulnerability data, reports, and analysis results will be permanently removed.</span>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="mt-6">
            <AlertDialogCancel className="bg-slate-700 hover:bg-slate-600 text-white border-slate-600">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction 
              onClick={handleDeleteScan}
              className="bg-red-600 hover:bg-red-700 text-white"
              disabled={!!deletingId}
            >
              {deletingId ? (
                <span className="flex items-center gap-2">
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Deleting...
                </span>
              ) : (
                'Delete Scan'
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
