import React from 'react'
import { createRoot } from 'react-dom/client'
import './fonts.css'
import './index.css'
import Join from './Join.jsx'

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <Join />
  </React.StrictMode>,
)
