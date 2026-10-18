"use client"

import { useState, useEffect } from "react"
import { Book, ArrowLeft, Search, Menu, X, BookOpen, Code, Shield } from "lucide-react"
import Link from "next/link"
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Button } from "@/components/ui/button"
import { DocNavigation } from "@/components/DocNavigation"

export default function DocumentationPage() {
  const [content, setContent] = useState("")
  const [searchTerm, setSearchTerm] = useState("")
  const [loading, setLoading] = useState(true)
  const [activeSection, setActiveSection] = useState("overview")
  const [activeSubsection, setActiveSubsection] = useState<string | undefined>()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  useEffect(() => {
    // Fetch documentation content
    fetch('/DOCUMENTATION.md')
      .then(res => res.text())
      .then(text => {
        setContent(text)
        setLoading(false)
      })
      .catch(err => {
        console.error('Failed to load documentation:', err)
        setLoading(false)
      })
  }, [])

  // Handle section click from navigation
  const handleSectionClick = (sectionId: string, subsectionId?: string) => {
    setActiveSection(sectionId)
    setActiveSubsection(subsectionId)
    
    // Map navigation IDs to actual heading IDs in the markdown
    const idMap: { [key: string]: string } = {
      'overview': 'overview',
      'intro': 'overview',
      'features': 'features',
      'architecture': 'architecture',
      'static-analysis': '1-static-analysis',
      'manifest': 'manifest-security',
      'permissions': 'permission-analysis',
      'code': 'code-security',
      'apis': '1-static-analysis',
      'crypto': '6-weak-cryptography',
      'strings': '1-static-analysis',
      'dynamic-analysis': 'features',
      'runtime': 'features',
      'network': '8-network-security',
      'behavior': 'features',
      'adb': 'features',
      'api-reference': 'api-documentation',
      'endpoints': 'scan-endpoints',
      'authentication': 'authentication-endpoints',
      'upload': 'upload-apk',
      'analysis': 'get-scan-details',
      'deployment': 'installation-setup',
      'setup': 'installation-setup',
      'docker': 'installation-setup',
      'config': 'installation-setup',
      'troubleshooting': 'troubleshooting',
      'security': 'security-analysis',
      'best-practices': 'security-analysis',
      'data-protection': 'security-analysis',
      'compliance': 'security-analysis',
    }
    
    // Get the target ID
    const targetId = subsectionId || sectionId
    const mappedId = idMap[targetId] || targetId
    
    // Try to find the element
    setTimeout(() => {
      const element = document.getElementById(mappedId)
      if (element) {
        const yOffset = -100 // Offset for fixed header
        const y = element.getBoundingClientRect().top + window.pageYOffset + yOffset
        window.scrollTo({ top: y, behavior: 'smooth' })
      }
    }, 100)
    
    // Close sidebar on mobile after selection
    setSidebarOpen(false)
  }

  // Filter content based on search
  const filteredContent = searchTerm 
    ? content.split('\n').filter(line => 
        line.toLowerCase().includes(searchTerm.toLowerCase())
      ).join('\n')
    : content

  return (
    <div className="flex gap-6 max-w-[1800px] mx-auto relative min-h-screen">
      {/* Mobile Menu Toggle */}
      <Button
        variant="outline"
        size="sm"
        className="lg:hidden fixed top-20 left-4 z-50 border-slate-600 text-slate-300 hover:bg-slate-800 shadow-lg"
        onClick={() => setSidebarOpen(!sidebarOpen)}
      >
        {sidebarOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
        <span className="ml-2 text-xs">{sidebarOpen ? 'Close' : 'Menu'}</span>
      </Button>

      {/* Sidebar Navigation */}
      <aside className={`
        fixed lg:sticky top-16 lg:top-4 left-0 h-[calc(100vh-5rem)] lg:max-h-[calc(100vh-2rem)] w-80 
        glassmorphism rounded-lg cyber-border p-5 overflow-y-auto
        transition-transform duration-300 z-40
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
        scrollbar-thin scrollbar-thumb-cyan-500/50 scrollbar-track-slate-800/50
        scrollbar-thin scrollbar-thumb-cyan-500/50 scrollbar-track-slate-800/50
      `}>
        <div className="flex items-center justify-between mb-6 pb-4 border-b-2 border-cyan-500/30">
          <div className="flex items-center gap-2">
            <Book className="w-5 h-5 text-cyan-400" />
            <h2 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">Navigation</h2>
          </div>
          <Button
            variant="ghost"
            size="sm"
            className="lg:hidden text-slate-400 hover:text-white"
            onClick={() => setSidebarOpen(false)}
          >
            <X className="w-4 h-4" />
          </Button>
        </div>
        
        <DocNavigation
          onSectionClick={handleSectionClick}
          activeSection={activeSection}
          activeSubsection={activeSubsection}
        />
      </aside>

      {/* Overlay for mobile */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-30 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Main Content */}
      <div className="flex-1 min-w-0 pb-12">
        {/* Header */}
        <div className="mb-8 sticky top-0 z-10 bg-slate-900/80 backdrop-blur-sm pb-4 pt-2 -mt-2">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <Link href="/dashboard">
              <Button variant="outline" size="sm" className="border-slate-600 text-slate-300 hover:bg-slate-800 hover:border-cyan-500/50 transition-all">
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back to Dashboard
              </Button>
            </Link>
            <div className="flex-1">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-gradient-to-br from-cyan-500/20 to-purple-500/20 rounded-lg border border-cyan-500/30">
                  <Book className="w-6 h-6 text-cyan-400" />
                </div>
                <div>
                  <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">Documentation</h1>
                  <p className="text-slate-400 text-sm mt-1">Comprehensive guide to FalconScan</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Search Bar */}
        <div className="mb-6">
          <div className="relative">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
            <input
              type="text"
              placeholder="Search documentation..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              autoComplete="off"
              className="w-full pl-12 pr-4 py-3.5 bg-slate-800/50 border-2 border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/70 focus:ring-2 focus:ring-cyan-500/20 transition-all backdrop-blur-sm"
            />
          </div>
        </div>

        {/* Documentation Content */}
        <div className="glassmorphism rounded-xl cyber-border p-8 md:p-10 shadow-2xl shadow-cyan-500/5">
          {loading ? (
            <div className="text-center py-12">
              <div className="inline-block p-4 bg-cyan-500/20 rounded-full mb-4">
                <div className="animate-spin">
                  <Book className="w-8 h-8 text-cyan-400" />
                </div>
              </div>
              <p className="text-slate-400">Loading documentation...</p>
            </div>
          ) : (
            <div className="prose prose-invert prose-slate max-w-none">
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                  h1: ({ children }) => (
                    <h1 id="overview" className="text-5xl font-extrabold bg-gradient-to-r from-cyan-400 via-purple-400 to-pink-400 bg-clip-text text-transparent mb-8 pb-4 border-b-2 border-cyan-500/50">{children}</h1>
                  ),
                  h2: ({ children }) => {
                    const id = String(children).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').replace(/-{2,}/g, '-')
                    return (
                      <h2 id={id} className="text-2xl font-bold text-white mt-10 mb-4 pb-3 border-b border-slate-700/70 scroll-mt-24">
                        {children}
                      </h2>
                    )
                  },
                  h3: ({ children }) => {
                    const id = String(children).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').replace(/-{2,}/g, '-')
                    return (
                      <h3 id={id} className="text-lg font-semibold text-cyan-400 mt-8 mb-3 scroll-mt-24">
                        {children}
                      </h3>
                    )
                  },
                  h4: ({ children }) => {
                    const id = String(children).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').replace(/-{2,}/g, '-')
                    return (
                      <h4 id={id} className="text-base font-semibold text-purple-300 mt-5 mb-2 scroll-mt-24">{children}</h4>
                    )
                  },
                  p: ({ children }) => (
                    <p className="text-slate-300 leading-relaxed mb-4 text-sm">{children}</p>
                  ),
                  a: ({ href, children }) => (
                    <a href={href} className="text-cyan-400 hover:text-cyan-300 underline decoration-cyan-500/50 hover:decoration-cyan-300 transition-all">{children}</a>
                  ),
                  ul: ({ children }) => (
                    <ul className="list-none text-slate-300 mb-4 space-y-1.5">{children}</ul>
                  ),
                  ol: ({ children }) => (
                    <ol className="list-decimal list-inside text-slate-300 mb-4 space-y-1.5 ml-4">{children}</ol>
                  ),
                  li: ({ children }) => (
                    <li className="text-slate-300 text-sm ml-4 before:content-['▹'] before:text-cyan-500 before:font-bold before:-ml-4 before:mr-2">{children}</li>
                  ),
                  code: ({ className, children, ...props }: any) => {
                    const isMermaid = className?.includes('language-mermaid')
                    const isInline = !className
                    
                    if (isMermaid) {
                      return (
                        <div className="not-prose my-8 p-6 bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 rounded-xl border-2 border-cyan-500/30 shadow-2xl shadow-cyan-500/10">
                          <div className="flex items-center gap-2 mb-4 pb-3 border-b border-cyan-500/30">
                            <div className="w-3 h-3 rounded-full bg-red-500"></div>
                            <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                            <div className="w-3 h-3 rounded-full bg-green-500"></div>
                            <span className="ml-2 text-cyan-400 text-sm font-mono">diagram.mermaid</span>
                          </div>
                          <pre className="text-cyan-300 text-sm overflow-x-auto font-mono leading-relaxed whitespace-pre-wrap">{children}</pre>
                          <div className="mt-4 pt-3 border-t border-cyan-500/20 text-xs text-slate-400 italic flex items-center gap-2">
                            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                            </svg>
                            Note: Mermaid diagrams render as interactive flowcharts in compatible viewers
                          </div>
                        </div>
                      )
                    }
                    
                    if (isInline) {
                      return (
                        <code className="px-2.5 py-1 bg-gradient-to-r from-purple-500/20 to-cyan-500/20 text-cyan-300 rounded-md text-sm font-mono border border-cyan-500/30 shadow-sm" {...props}>
                          {children}
                        </code>
                      )
                    }
                    
                    // Block code - return the code element only, pre wrapper handles the rest
                    return (
                      <code className="block p-5 bg-gradient-to-br from-slate-900 to-black text-green-400 rounded-b-lg overflow-x-auto text-sm font-mono border-l-4 border-green-500/50 shadow-xl leading-relaxed" {...props}>
                        {children}
                      </code>
                    )
                  },
                  pre: ({ children, ...props }) => {
                    // Extract className from children if it exists
                    const childProps = (children as any)?.props
                    const className = childProps?.className || ''
                    const langName = className.replace('language-', '') || 'code'
                    
                    return (
                      <div className="not-prose my-6">
                        <div className="flex items-center gap-2 px-4 py-2 bg-slate-800 rounded-t-lg border-b border-slate-700">
                          <div className="w-3 h-3 rounded-full bg-red-500"></div>
                          <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                          <div className="w-3 h-3 rounded-full bg-green-500"></div>
                          <span className="ml-2 text-slate-400 text-xs font-mono">{langName}</span>
                        </div>
                        <pre {...props}>{children}</pre>
                      </div>
                    )
                  },
                  blockquote: ({ children }) => (
                    <blockquote className="border-l-4 border-cyan-500/60 bg-cyan-500/5 pl-5 pr-4 py-3 italic text-slate-300 text-sm my-5 rounded-r-lg">
                      {children}
                    </blockquote>
                  ),
                  table: ({ children }) => (
                    <div className="overflow-x-auto mb-8 rounded-lg border border-slate-700 shadow-xl">
                      <table className="w-full border-collapse">
                        {children}
                      </table>
                    </div>
                  ),
                  thead: ({ children }) => (
                    <thead className="bg-gradient-to-r from-cyan-900/50 to-purple-900/50">{children}</thead>
                  ),
                  tbody: ({ children }) => (
                    <tbody className="bg-slate-800/30">{children}</tbody>
                  ),
                  tr: ({ children }) => (
                    <tr className="border-b border-slate-700 hover:bg-cyan-500/5 transition-colors">{children}</tr>
                  ),
                  th: ({ children }) => (
                    <th className="px-4 py-3 text-left text-cyan-400 font-semibold border border-slate-700">
                      {children}
                    </th>
                  ),
                  td: ({ children }) => (
                    <td className="px-4 py-2.5 text-slate-300 text-sm border border-slate-700">
                      {children}
                    </td>
                  ),
                  hr: () => (
                    <hr className="my-8 border-slate-700/60" />
                  ),
                  strong: ({ children }) => (
                    <strong className="text-white font-semibold">{children}</strong>
                  ),
                  em: ({ children }) => (
                    <em className="text-cyan-300 not-italic">{children}</em>
                  ),
                  img: ({ src, alt }) => (
                    <span className="block my-6">
                      <img
                        src={src}
                        alt={alt || ''}
                        className="rounded-xl border border-slate-700 max-w-full shadow-2xl shadow-black/40"
                        onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none' }}
                      />
                      {alt && (
                        <span className="block text-center text-xs text-slate-500 mt-2 italic">{alt}</span>
                      )}
                    </span>
                  ),
                }}
              >
                {filteredContent}
              </ReactMarkdown>
            </div>
          )}
        </div>

        {/* Quick Links */}
        <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-4">
          <div 
            className="glassmorphism p-5 rounded-xl cyber-border hover:border-cyan-500/50 hover:shadow-lg hover:shadow-cyan-500/10 transition-all cursor-pointer group" 
            onClick={() => handleSectionClick('user-guide', 'getting-started')}
          >
            <div className="flex items-start gap-3">
              <div className="p-2 bg-cyan-500/20 rounded-lg group-hover:bg-cyan-500/30 transition-colors">
                <BookOpen className="w-5 h-5 text-cyan-400" />
              </div>
              <div>
                <h3 className="text-white font-semibold mb-2 group-hover:text-cyan-400 transition-colors">Quick Start</h3>
                <p className="text-slate-400 text-sm leading-relaxed">Get started with uploading and analyzing your first APK</p>
              </div>
            </div>
          </div>
          <div 
            className="glassmorphism p-5 rounded-xl cyber-border hover:border-purple-500/50 hover:shadow-lg hover:shadow-purple-500/10 transition-all cursor-pointer group" 
            onClick={() => handleSectionClick('api-reference', 'auth-endpoints')}
          >
            <div className="flex items-start gap-3">
              <div className="p-2 bg-purple-500/20 rounded-lg group-hover:bg-purple-500/30 transition-colors">
                <Code className="w-5 h-5 text-purple-400" />
              </div>
              <div>
                <h3 className="text-white font-semibold mb-2 group-hover:text-purple-400 transition-colors">API Reference</h3>
                <p className="text-slate-400 text-sm leading-relaxed">Complete API documentation with examples</p>
              </div>
            </div>
          </div>
          <div 
            className="glassmorphism p-5 rounded-xl cyber-border hover:border-pink-500/50 hover:shadow-lg hover:shadow-pink-500/10 transition-all cursor-pointer group" 
            onClick={() => handleSectionClick('security-analysis', 'vuln-categories')}
          >
            <div className="flex items-start gap-3">
              <div className="p-2 bg-pink-500/20 rounded-lg group-hover:bg-pink-500/30 transition-colors">
                <Shield className="w-5 h-5 text-pink-400" />
              </div>
              <div>
                <h3 className="text-white font-semibold mb-2 group-hover:text-pink-400 transition-colors">Security Guide</h3>
                <p className="text-slate-400 text-sm leading-relaxed">Understanding vulnerability detection and remediation</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
