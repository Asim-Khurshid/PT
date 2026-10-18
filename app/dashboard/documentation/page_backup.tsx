"use client"

import { useState, useEffect } from "react"
import { Book, ArrowLeft, Search } from "lucide-react"
import Link from "next/link"
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Button } from "@/components/ui/button"

export default function DocumentationPage() {
  const [content, setContent] = useState("")
  const [searchTerm, setSearchTerm] = useState("")
  const [loading, setLoading] = useState(true)

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

  // Filter content based on search
  const filteredContent = searchTerm 
    ? content.split('\n').filter(line => 
        line.toLowerCase().includes(searchTerm.toLowerCase())
      ).join('\n')
    : content

  return (
    <div className="max-w-5xl mx-auto">
      {/* Header */}
      <div className="mb-8 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href="/dashboard">
            <Button variant="outline" size="sm" className="border-slate-600 text-slate-300 hover:bg-slate-800">
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to Dashboard
            </Button>
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-cyan-500/20 rounded-lg">
                <Book className="w-6 h-6 text-cyan-400" />
              </div>
              <h1 className="text-3xl font-bold text-white">Documentation</h1>
            </div>
            <p className="text-slate-400 mt-2">Comprehensive guide to FalconScan APK Security Analysis Platform</p>
          </div>
        </div>
      </div>

      {/* Search Bar */}
      <div className="mb-6">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
          <input
            type="text"
            placeholder="Search documentation..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            autoComplete="off"
            className="w-full pl-10 pr-4 py-3 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50 transition"
          />
        </div>
      </div>

      {/* Documentation Content */}
      <div className="glassmorphism rounded-lg cyber-border p-8">
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
                  <h1 className="text-5xl font-extrabold bg-gradient-to-r from-cyan-400 via-purple-400 to-pink-400 bg-clip-text text-transparent mb-8 pb-4 border-b-2 border-cyan-500/50">{children}</h1>
                ),
                h2: ({ children }) => (
                  <h2 className="text-4xl font-bold text-white mt-10 mb-6 pb-3 border-b border-cyan-500/30 flex items-center gap-3">
                    <span className="text-3xl">🔷</span>
                    {children}
                  </h2>
                ),
                h3: ({ children }) => (
                  <h3 className="text-3xl font-semibold text-cyan-400 mt-8 mb-4 flex items-center gap-2">
                    <span className="text-2xl">🔸</span>
                    {children}
                  </h3>
                ),
                h4: ({ children }) => (
                  <h4 className="text-2xl font-semibold bg-gradient-to-r from-purple-400 to-cyan-400 bg-clip-text text-transparent mt-6 mb-3">{children}</h4>
                ),
                p: ({ children }) => (
                  <p className="text-slate-300 leading-relaxed mb-5 text-lg">{children}</p>
                ),
                a: ({ href, children }) => (
                  <a href={href} className="text-cyan-400 hover:text-cyan-300 underline decoration-cyan-500/50 hover:decoration-cyan-300 transition-all">{children}</a>
                ),
                ul: ({ children }) => (
                  <ul className="list-none text-slate-300 mb-6 space-y-3">{children}</ul>
                ),
                ol: ({ children }) => (
                  <ol className="list-decimal list-inside text-slate-300 mb-6 space-y-3 ml-4">{children}</ol>
                ),
                li: ({ children }) => (
                  <li className="text-slate-300 ml-6 before:content-['▹'] before:text-cyan-400 before:font-bold before:-ml-6 before:mr-2">{children}</li>
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
                  <blockquote className="border-l-4 border-cyan-500 bg-cyan-500/5 pl-6 pr-4 py-4 italic text-slate-300 my-6 rounded-r-lg">
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
                  <td className="px-4 py-3 text-slate-300 border border-slate-700">
                    {children}
                  </td>
                ),
                hr: () => (
                  <hr className="my-8 border-slate-700" />
                ),
                strong: ({ children }) => (
                  <strong className="text-white font-semibold">{children}</strong>
                ),
                em: ({ children }) => (
                  <em className="text-cyan-400">{children}</em>
                ),
              }}
            >
              {filteredContent}
            </ReactMarkdown>
          </div>
        )}
      </div>

      {/* Quick Links */}
      <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glassmorphism p-4 rounded-lg cyber-border">
          <h3 className="text-white font-semibold mb-2">Quick Start</h3>
          <p className="text-slate-400 text-sm">Get started with uploading and analyzing your first APK</p>
        </div>
        <div className="glassmorphism p-4 rounded-lg cyber-border">
          <h3 className="text-white font-semibold mb-2">API Reference</h3>
          <p className="text-slate-400 text-sm">Complete API documentation with examples</p>
        </div>
        <div className="glassmorphism p-4 rounded-lg cyber-border">
          <h3 className="text-white font-semibold mb-2">Security Guide</h3>
          <p className="text-slate-400 text-sm">Understanding vulnerability detection and remediation</p>
        </div>
      </div>
    </div>
  )
}
