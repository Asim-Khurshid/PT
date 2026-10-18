"use client"

import { useState, useEffect } from "react"
import { Search, MoreVertical, Eye } from "lucide-react"
import Link from "next/link"
import { scansAPI } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"

export default function ScanHistoryPage() {
  const { toast } = useToast()
  const [searchTerm, setSearchTerm] = useState("")
  const [filterRisk, setFilterRisk] = useState("all")
  const [scans, setScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    scansAPI.list()
      .then(res => {
        setScans(res.data.results || res.data || [])
        setLoading(false)
      })
      .catch(err => {
        console.error('Failed to fetch scans:', err)
        toast({ title: "Error", description: "Failed to load scan history", variant: "destructive" })
        setLoading(false)
      })
  }, [])

  const filteredScans = scans.filter(
    (scan) =>
      scan.app_name?.toLowerCase().includes(searchTerm.toLowerCase()) &&
      (filterRisk === "all" || scan.threat_level?.toLowerCase() === filterRisk.toLowerCase()),
  )

  const getRiskColor = (risk: string) => {
    switch (risk?.toLowerCase()) {
      case "critical":
        return "bg-red-500/20 text-red-400"
      case "high":
        return "bg-orange-500/20 text-orange-400"
      case "medium":
        return "bg-yellow-500/20 text-yellow-400"
      case "low":
        return "bg-green-500/20 text-green-400"
      case "safe":
        return "bg-green-500/20 text-green-400"
      default:
        return "bg-slate-500/20 text-slate-400"
    }
  }

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    const now = new Date()
    const diff = now.getTime() - date.getTime()
    const hours = Math.floor(diff / (1000 * 60 * 60))
    const days = Math.floor(hours / 24)
    
    if (hours < 1) return "Just now"
    if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`
    if (days < 7) return `${days} day${days > 1 ? 's' : ''} ago`
    return date.toLocaleDateString()
  }

  const formatSize = (bytes: number) => {
    if (!bytes) return "N/A"
    return (bytes / 1024 / 1024).toFixed(1) + " MB"
  }

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Scan History</h1>
        <p className="text-slate-400 mt-2">View all your previous APK analyses</p>
      </div>

      {/* Filters */}
      <div className="flex gap-4 mb-6 flex-wrap">
        <div className="flex-1 min-w-64">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search APKs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              autoComplete="off"
              className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-300 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 cursor-text"
            />
          </div>
        </div>

        <select
          value={filterRisk}
          onChange={(e) => setFilterRisk(e.target.value)}
          className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-300 focus:outline-none focus:border-cyan-500 cursor-pointer"
        >
          <option value="all">All Risk Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {loading ? (
          <div className="col-span-full text-center py-12">
            <p className="text-slate-400">Loading scans...</p>
          </div>
        ) : filteredScans.length > 0 ? (
          filteredScans.map((scan) => (
            <div
              key={scan.id}
              className="glassmorphism p-6 rounded-lg cyber-border hover:cyber-border-hover transition group"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-start gap-3 flex-1">
                  <div className="text-3xl">📦</div>
                  <div className="flex-1">
                    <h3 className="text-white font-semibold truncate">{scan.app_name}</h3>
                    <p className="text-slate-400 text-xs mt-1">{formatDate(scan.created_at)}</p>
                  </div>
                </div>
                <button className="p-2 opacity-0 group-hover:opacity-100 hover:bg-slate-700 rounded-lg transition text-slate-400 hover:text-cyan-400 cursor-pointer">
                  <MoreVertical className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 text-xs">Risk Level</span>
                  <span className={`px-2 py-1 rounded-full text-xs font-semibold capitalize ${getRiskColor(scan.threat_level)}`}>
                    {scan.threat_level || 'Safe'}
                  </span>
                </div>

                <div className="grid grid-cols-3 gap-2 text-center">
                  <div className="bg-slate-800/50 p-2 rounded">
                    <p className="text-cyan-400 font-bold">{scan.total_issues || 0}</p>
                    <p className="text-xs text-slate-400">Issues</p>
                  </div>
                  <div className="bg-slate-800/50 p-2 rounded">
                    <p className="text-cyan-400 font-bold">{scan.threat_score || 0}</p>
                    <p className="text-xs text-slate-400">Score</p>
                  </div>
                  <div className="bg-slate-800/50 p-2 rounded">
                    <p className="text-cyan-400 font-bold text-xs">{formatSize(scan.file_size)}</p>
                    <p className="text-xs text-slate-400">Size</p>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-700">
                  <Link
                    href={`/dashboard/reports/${scan.id}`}
                    className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 rounded-lg transition font-medium text-sm cursor-pointer"
                  >
                    <Eye className="w-4 h-4" />
                    View Report
                  </Link>
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="col-span-full text-center py-12">
            <p className="text-slate-400">{loading ? 'Loading...' : 'No scans found'}</p>
          </div>
        )}
      </div>
    </div>
  )
}
