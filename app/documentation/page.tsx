"use client"

import { useState, useEffect } from "react"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card } from "@/components/ui/card"
import { ArrowLeft, Search, Menu, X } from "lucide-react"
import Link from "next/link"
import { DocNavigation } from "@/components/DocNavigation"

export default function DocumentationPage() {
  const [content, setContent] = useState("")
  const [searchQuery, setSearchQuery] = useState("")
  const [loading, setLoading] = useState(true)
  const [activeSection, setActiveSection] = useState("overview")
  const [activeSubsection, setActiveSubsection] = useState<string>()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  useEffect(() => {
    fetch("/DOCUMENTATION.md")
      .then((res) => res.text())
      .then((text) => {
        setContent(text)
        setLoading(false)
      })
      .catch((error) => {
        console.error("Error loading documentation:", error)
        setLoading(false)
      })
  }, [])

  const handleSectionClick = (sectionId: string, subsectionId?: string) => {
    setActiveSection(sectionId)
    setActiveSubsection(subsectionId)
    setMobileMenuOpen(false)
    // Scroll to section
    setTimeout(() => {
      const element = document.getElementById(sectionId)
      element?.scrollIntoView({ behavior: 'smooth' })
    }, 100)
  }

  const filteredContent = content
    .split("\n")
    .filter((line) => line.toLowerCase().includes(searchQuery.toLowerCase()))
    .join("\n")

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-background via-background to-secondary/10 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading documentation...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-secondary/10 flex flex-col">
      {/* Header */}
      <div className="border-b border-border/40 backdrop-blur-sm sticky top-0 z-50 bg-background/80">
        <div className="px-4 py-4">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="lg:hidden gap-2"
              >
                {sidebarOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
              </Button>
              <Link href="/">
                <Button variant="outline" size="sm" className="gap-2 cursor-pointer">
                  <ArrowLeft className="w-4 h-4" />
                  Back to Home
                </Button>
              </Link>
            </div>
            <h1 className="text-2xl font-bold text-foreground text-center flex-1">FalconScan Documentation</h1>
            <div className="w-32" />
          </div>

          {/* Search Bar */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground cursor-pointer" />
            <Input
              type="text"
              placeholder="Search documentation..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 bg-background/50 border-border/50 cursor-text"
            />
          </div>
        </div>
      </div>

      {/* Mobile Menu Button */}
      <div className="lg:hidden px-4 py-2 border-b border-border/40">
        <Button
          size="sm"
          variant={mobileMenuOpen ? "default" : "outline"}
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="w-full cursor-pointer"
        >
          {mobileMenuOpen ? "Hide Navigation" : "Show Navigation"}
        </Button>
      </div>

      {/* Main Content */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar - Navigation */}
        {(sidebarOpen || mobileMenuOpen) && (
          <div className="w-full lg:w-64 border-r border-border/40 bg-slate-900/50 p-4 overflow-y-auto lg:sticky lg:top-20 lg:h-[calc(100vh-80px)]">
            <DocNavigation
              onSectionClick={handleSectionClick}
              activeSection={activeSection}
              activeSubsection={activeSubsection}
            />
          </div>
        )}

        {/* Main Documentation Content */}
        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center min-h-screen">
              <div className="text-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
                <p className="text-muted-foreground">Loading documentation...</p>
              </div>
            </div>
          ) : (
            <div className="max-w-4xl mx-auto px-4 py-8">
              <Card className="glassmorphism border-0 p-8">
                <div className="prose prose-invert max-w-none">
                  <ReactMarkdown
                    remarkPlugins={[remarkGfm]}
                    components={{
                h1: ({ children }) => (
                  <h1 className="text-5xl font-extrabold bg-gradient-to-r from-cyan-400 via-purple-400 to-pink-400 bg-clip-text text-transparent mb-8 pb-4 border-b-2 border-cyan-500/50">
                    {children}
                  </h1>
                ),
                h2: ({ children }) => (
                  <h2 className="text-4xl font-bold text-foreground mt-10 mb-6 pb-3 border-b border-cyan-500/30 flex items-center gap-3">
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
                p: ({ children }) => <p className="text-muted-foreground mb-5 leading-relaxed text-lg">{children}</p>,
                ul: ({ children }) => <ul className="list-none mb-6 space-y-3 text-muted-foreground">{children}</ul>,
                ol: ({ children }) => <ol className="list-decimal list-inside mb-6 space-y-3 text-muted-foreground ml-4">{children}</ol>,
                li: ({ children }) => <li className="text-muted-foreground ml-6 before:content-['▹'] before:text-cyan-400 before:font-bold before:-ml-6 before:mr-2">{children}</li>,
                code: ({ inline, children, className, ...props }: any) => {
                  const isMermaid = className?.includes('language-mermaid')
                  const isInline = inline !== false && !className
                  
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
                        <div className="mt-4 pt-3 border-t border-cyan-500/20 text-xs text-muted-foreground italic flex items-center gap-2">
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
                      <code className="px-2.5 py-1 bg-gradient-to-r from-purple-500/20 to-cyan-500/20 text-cyan-400 rounded-md text-sm font-mono border border-cyan-500/30 shadow-sm" {...props}>
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
                      <div className="flex items-center gap-2 px-4 py-2 bg-background/80 rounded-t-lg border-b border-border/40">
                        <div className="w-3 h-3 rounded-full bg-red-500"></div>
                        <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                        <div className="w-3 h-3 rounded-full bg-green-500"></div>
                        <span className="ml-2 text-muted-foreground text-xs font-mono">{langName}</span>
                      </div>
                      <pre {...props}>{children}</pre>
                    </div>
                  )
                },
                a: ({ children, href }) => (
                  <a href={href} className="text-cyan-400 hover:text-cyan-300 underline decoration-cyan-500/50 hover:decoration-cyan-300 transition-all">
                    {children}
                  </a>
                ),
                blockquote: ({ children }) => (
                  <blockquote className="border-l-4 border-primary bg-primary/5 pl-6 pr-4 py-4 italic text-muted-foreground my-6 rounded-r-lg">
                    {children}
                  </blockquote>
                ),
                table: ({ children }) => (
                  <div className="overflow-x-auto mb-8 rounded-lg border border-border/40 shadow-xl">
                    <table className="min-w-full border-collapse">{children}</table>
                  </div>
                ),
                thead: ({ children }) => <thead className="bg-gradient-to-r from-cyan-900/50 to-purple-900/50">{children}</thead>,
                tbody: ({ children }) => <tbody className="divide-y divide-border/40">{children}</tbody>,
                tr: ({ children }) => <tr className="hover:bg-primary/5 transition-colors">{children}</tr>,
                th: ({ children }) => (
                  <th className="px-4 py-3 text-left text-foreground font-semibold border-b border-border/40">
                    {children}
                  </th>
                ),
                td: ({ children }) => <td className="px-4 py-3 text-muted-foreground">{children}</td>,
              }}
            >
              {searchQuery ? filteredContent : content}
                  </ReactMarkdown>
                </div>

                {/* Quick Links */}
                <div className="mt-8 pt-6 border-t border-border/40">
                  <h3 className="text-lg font-semibold text-foreground mb-4">Quick Links</h3>
                  <div className="grid md:grid-cols-3 gap-4">
                    <Card className="p-4 border-primary/20 hover:border-primary/40 transition-colors cursor-pointer">
                      <h4 className="font-semibold text-primary mb-2">Quick Start</h4>
                      <p className="text-sm text-muted-foreground">Get started with FalconScan in minutes</p>
                    </Card>
                    <Card className="p-4 border-cyan-500/20 hover:border-cyan-500/40 transition-colors cursor-pointer">
                      <h4 className="font-semibold text-cyan-400 mb-2">API Reference</h4>
                      <p className="text-sm text-muted-foreground">Complete API documentation</p>
                    </Card>
                    <Card className="p-4 border-purple-500/20 hover:border-purple-500/40 transition-colors cursor-pointer">
                      <h4 className="font-semibold text-purple-400 mb-2">Security Guide</h4>
                      <p className="text-sm text-muted-foreground">Learn about security features</p>
                    </Card>
                  </div>
                </div>
              </Card>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
