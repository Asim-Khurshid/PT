"use client"

import { useState, useEffect } from "react"
import { BarChart3, AlertTriangle, Package, TrendingUp, ArrowUp, ArrowDown, Eye } from "lucide-react"
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts"
import { Button } from "@/components/ui/button"
import Link from "next/link"
import { scansAPI } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"

export default function DashboardPage() {
  const { toast } = useToast()
  const [stats, setStats] = useState<any>(null)
  const [recentScans, setRecentScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Auto-cleanup failed scans on dashboard load
    scansAPI.cleanupFailed()
      .then(res => {
        if (res.data.cleaned > 0) {
          toast({
            title: "Auto-Recovery",
            description: `Automatically retrying ${res.data.cleaned} failed scan${res.data.cleaned > 1 ? 's' : ''}`,
          })
        }
      })
      .catch(err => {
        console.error('Auto-cleanup failed:', err)
      })

    Promise.all([
      scansAPI.statistics(),
      scansAPI.list()
    ])
      .then(([statsRes, scansRes]) => {
        setStats(statsRes.data)
        setRecentScans((scansRes.data.results || scansRes.data || []).slice(0, 4))
        setLoading(false)
      })
      .catch(err => {
        console.error('Failed to fetch dashboard data:', err)
        toast({ title: "Error", description: "Failed to load dashboard data", variant: "destructive" })
        setLoading(false)
      })
  }, [])
  // Stats data
  const statsData = [
    { label: "Total Scans", value: stats?.total_scans || 0, trend: "+12%", icon: BarChart3, color: "from-cyan-500 to-cyan-600" },
    { label: "Critical Issues", value: stats?.critical_threats || 0, trend: "-5%", icon: AlertTriangle, color: "from-red-500 to-red-600" },
    { label: "APKs Analyzed", value: stats?.total_scans || 0, trend: "+8%", icon: Package, color: "from-blue-500 to-blue-600" },
    { label: "Safe Apps", value: stats?.safe_apps || 0, trend: "+2%", icon: TrendingUp, color: "from-green-500 to-green-600" },
  ]

  // Chart data
  const chartData = [
    { name: "Mon", scans: 45, threats: 12 },
    { name: "Tue", scans: 52, threats: 15 },
    { name: "Wed", scans: 48, threats: 10 },
    { name: "Thu", scans: 61, threats: 18 },
    { name: "Fri", scans: 55, threats: 14 },
    { name: "Sat", scans: 38, threats: 8 },
    { name: "Sun", scans: 42, threats: 11 },
  ]

  const riskData = [
    { name: "Critical", value: stats?.critical_threats || 0, color: "#ef4444" },
    { name: "High", value: stats?.high_threats || 0, color: "#f59e0b" },
    { name: "Medium", value: stats?.medium_threats || 0, color: "#eab308" },
    { name: "Low", value: stats?.safe_apps || 0, color: "#10b981" },
  ]

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

  const getRiskColor = (level: string) => {
    switch(level?.toLowerCase()) {
      case 'critical': return 'bg-red-500/20 text-red-400'
      case 'high': return 'bg-orange-500/20 text-orange-400'
      case 'medium': return 'bg-yellow-500/20 text-yellow-400'
      case 'low': return 'bg-green-500/20 text-green-400'
      default: return 'bg-green-500/20 text-green-400'
    }
  }

  const recentScansData = recentScans.map(scan => ({
    id: scan.id,
    name: scan.app_name,
    date: formatDate(scan.created_at),
    risk: scan.threat_level || 'Safe',
    status: scan.status === 'completed' ? 'Completed' : 'Processing',
    threats: scan.total_issues || 0
  }))

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white">Dashboard</h1>
        <p className="text-slate-400 mt-2">Welcome back. Here's your security overview.</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {loading ? (
          <div className="col-span-full text-center py-12">
            <p className="text-slate-400">Loading statistics...</p>
          </div>
        ) : (
          statsData.map((stat, idx) => (
            <div
              key={idx}
              className="glassmorphism p-6 rounded-lg cyber-border hover:cyber-border-hover transition group"
            >
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-slate-400 text-sm">{stat.label}</p>
                  <p className="text-3xl font-bold text-white mt-2">{stat.value}</p>
                  <div className="flex items-center gap-1 mt-2">
                    {stat.trend.startsWith("+") ? (
                      <ArrowUp className="w-4 h-4 text-green-500" />
                    ) : (
                      <ArrowDown className="w-4 h-4 text-red-500" />
                    )}
                    <span
                      className={stat.trend.startsWith("+") ? "text-green-500" : "text-red-500"}
                      style={{ fontSize: "12px" }}
                    >
                      {stat.trend}
                    </span>
                  </div>
                </div>
                <div className={`bg-gradient-to-br ${stat.color} p-3 rounded-lg group-hover:cyber-glow transition`}>
                  <stat.icon className="w-6 h-6 text-white" />
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Quick Actions */}
      <div className="flex gap-4 flex-wrap">
        <Link href="/dashboard/upload">
          <Button className="bg-gradient-to-r from-cyan-500 to-cyan-600 hover:from-cyan-600 hover:to-cyan-700 text-slate-950 font-semibold cyber-glow-hover cursor-pointer">
            Upload New APK
          </Button>
        </Link>
        <Link href="/dashboard/reports">
          <Button variant="outline" className="border-cyan-500/50 text-cyan-400 hover:bg-slate-800 bg-transparent cursor-pointer">
            View All Reports
          </Button>
        </Link>
        <Link href="/dashboard/documentation">
          <Button variant="outline" className="border-purple-500/50 text-purple-400 hover:bg-slate-800 bg-transparent cursor-pointer">
            📖 View Documentation
          </Button>
        </Link>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Line Chart */}
        <div className="lg:col-span-2 glassmorphism p-6 rounded-lg cyber-border">
          <h3 className="text-white font-semibold mb-4">Scans & Threats Over Time</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis stroke="#64748b" />
              <YAxis stroke="#64748b" />
              <Tooltip
                contentStyle={{ backgroundColor: "#1e293b", border: "1px solid #334155", borderRadius: "8px" }}
                labelStyle={{ color: "#f1f5f9" }}
              />
              <Legend />
              <Line type="monotone" dataKey="scans" stroke="#06b6d4" strokeWidth={2} dot={{ fill: "#06b6d4" }} />
              <Line type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2} dot={{ fill: "#ef4444" }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Pie Chart */}
        <div className="glassmorphism p-6 rounded-lg cyber-border">
          <h3 className="text-white font-semibold mb-4">Risk Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={riskData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={100}
                paddingAngle={2}
                dataKey="value"
              >
                {riskData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: "#1e293b", border: "1px solid #334155", borderRadius: "8px" }}
                labelStyle={{ color: "#f1f5f9" }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="mt-4 space-y-2 text-sm">
            {riskData.map((item, idx) => (
              <div key={idx} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-slate-400">{item.name}</span>
                </div>
                <span className="text-white font-semibold">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="glassmorphism p-6 rounded-lg cyber-border">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-white font-semibold">Recent Scans</h3>
          <Link href="/dashboard/history" className="text-cyan-400 hover:text-cyan-300 text-sm transition">
            View All
          </Link>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="text-left py-3 px-4 text-slate-400 font-medium text-sm">APK Name</th>
                <th className="text-left py-3 px-4 text-slate-400 font-medium text-sm">Upload Date</th>
                <th className="text-left py-3 px-4 text-slate-400 font-medium text-sm">Risk Level</th>
                <th className="text-left py-3 px-4 text-slate-400 font-medium text-sm">Threats Found</th>
                <th className="text-left py-3 px-4 text-slate-400 font-medium text-sm">Status</th>
                <th className="text-center py-3 px-4 text-slate-400 font-medium text-sm">Action</th>
              </tr>
            </thead>
            <tbody>
              {recentScansData.map((scan, idx) => (
                <tr key={idx} className="border-b border-slate-700/50 hover:bg-slate-800/50 transition">
                  <td className="py-4 px-4 text-white font-medium">{scan.name}</td>
                  <td className="py-4 px-4 text-slate-400 text-sm">{scan.date}</td>
                  <td className="py-4 px-4">
                    <span
                      className={`px-3 py-1 rounded-full text-xs font-semibold capitalize ${getRiskColor(scan.risk)}`}
                    >
                      {scan.risk}
                    </span>
                  </td>
                  <td className="py-4 px-4 text-white font-medium">{scan.threats}</td>
                  <td className="py-4 px-4 text-green-400 text-sm">{scan.status}</td>
                  <td className="py-4 px-4 text-center">
                    <Link href={`/dashboard/reports/${scan.id}`}>
                      <button className="p-2 hover:bg-slate-700 rounded-lg transition text-cyan-400 hover:text-cyan-300 inline-flex">
                        <Eye className="w-4 h-4" />
                      </button>
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
