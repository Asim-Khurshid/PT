"use client"

import { useState, useRef, useEffect } from 'react'
import { Bell, X, Check, CheckCheck, Trash2, AlertCircle, CheckCircle, Info, AlertTriangle } from 'lucide-react'
import Link from 'next/link'
import { useNotifications } from '@/contexts/NotificationContext'
import { formatDistanceToNow } from 'date-fns'

export default function NotificationDropdown() {
  const [isOpen, setIsOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const { notifications, unreadCount, markAsRead, markAllAsRead, clearNotification, clearAll } = useNotifications()

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside)
      return () => document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [isOpen])

  const getIcon = (type: string) => {
    switch (type) {
      case 'success':
        return <CheckCircle className="w-5 h-5 text-green-400" />
      case 'error':
        return <AlertCircle className="w-5 h-5 text-red-400" />
      case 'warning':
        return <AlertTriangle className="w-5 h-5 text-yellow-400" />
      default:
        return <Info className="w-5 h-5 text-cyan-400" />
    }
  }

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'success':
        return 'border-green-500/30 bg-green-500/5'
      case 'error':
        return 'border-red-500/30 bg-red-500/5'
      case 'warning':
        return 'border-yellow-500/30 bg-yellow-500/5'
      default:
        return 'border-cyan-500/30 bg-cyan-500/5'
    }
  }

  return (
    <div className="relative" ref={dropdownRef}>
      {/* Bell Icon Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="relative p-2 hover:bg-slate-800 rounded-lg transition text-slate-400 hover:text-cyan-400 cursor-pointer"
      >
        <Bell className="w-5 h-5" />
        {unreadCount > 0 && (
          <span className="absolute top-1 right-1 flex items-center justify-center min-w-[18px] h-[18px] px-1 bg-red-500 text-white text-[10px] font-bold rounded-full">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {/* Dropdown Panel */}
      {isOpen && (
        <div className="absolute right-0 mt-2 w-96 bg-slate-900 border border-slate-700 rounded-lg shadow-2xl z-50 max-h-[600px] flex flex-col">
          {/* Header */}
          <div className="flex items-center justify-between p-4 border-b border-slate-700">
            <div>
              <h3 className="text-white font-semibold">Notifications</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                {unreadCount > 0 ? `${unreadCount} unread` : 'All caught up!'}
              </p>
            </div>
            <div className="flex items-center gap-2">
              {unreadCount > 0 && (
                <button
                  onClick={markAllAsRead}
                  className="p-1.5 text-cyan-400 hover:bg-slate-800 rounded transition cursor-pointer"
                  title="Mark all as read"
                >
                  <CheckCheck className="w-4 h-4" />
                </button>
              )}
              {notifications.length > 0 && (
                <button
                  onClick={clearAll}
                  className="p-1.5 text-red-400 hover:bg-slate-800 rounded transition cursor-pointer"
                  title="Clear all"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>

          {/* Notifications List */}
          <div className="flex-1 overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <Bell className="w-12 h-12 text-slate-600 mb-3" />
                <p className="text-slate-400 text-sm">No notifications yet</p>
                <p className="text-slate-500 text-xs mt-1">We'll notify you when something important happens</p>
              </div>
            ) : (
              <div className="divide-y divide-slate-700/50">
                {notifications.map((notification) => (
                  <div
                    key={notification.id}
                    className={`p-4 transition-colors ${
                      !notification.read ? 'bg-slate-800/50' : 'hover:bg-slate-800/30'
                    }`}
                  >
                    <div className="flex gap-3">
                      <div className="flex-shrink-0 mt-0.5">
                        {getIcon(notification.type)}
                      </div>
                      
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start justify-between gap-2">
                          <h4 className="text-sm font-semibold text-white">
                            {notification.title}
                          </h4>
                          <button
                            onClick={() => clearNotification(notification.id)}
                            className="flex-shrink-0 p-1 text-slate-500 hover:text-slate-300 transition cursor-pointer"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </div>
                        
                        <p className="text-xs text-slate-400 mt-1 line-clamp-2">
                          {notification.message}
                        </p>
                        
                        <div className="flex items-center gap-3 mt-2">
                          <span className="text-xs text-slate-500">
                            {formatDistanceToNow(notification.timestamp, { addSuffix: true })}
                          </span>
                          
                          {!notification.read && (
                            <button
                              onClick={() => markAsRead(notification.id)}
                              className="text-xs text-cyan-400 hover:text-cyan-300 transition cursor-pointer"
                            >
                              Mark as read
                            </button>
                          )}
                          
                          {notification.action && (
                            <Link
                              href={notification.action.href}
                              onClick={() => {
                                markAsRead(notification.id)
                                setIsOpen(false)
                              }}
                              className="text-xs text-cyan-400 hover:text-cyan-300 transition font-medium cursor-pointer"
                            >
                              {notification.action.label} →
                            </Link>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Footer */}
          {notifications.length > 0 && (
            <div className="p-3 border-t border-slate-700 bg-slate-800/50">
              <p className="text-xs text-center text-slate-400">
                Showing {notifications.length} notification{notifications.length !== 1 ? 's' : ''}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
