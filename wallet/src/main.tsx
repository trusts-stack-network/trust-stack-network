// Polyfills must be first
import './polyfills'

// Import test utilities (registers them on window)
import './test-poseidon'
import './test-prover'

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import './index.css'
import Wallet from './Wallet.tsx'
import Explorer from './Explorer.tsx'
import Landing from './Landing.tsx'
import PlonkyTest from './PlonkyTest.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter basename="/">
      <Routes>
        <Route path="/wallet/*" element={<Wallet />} />
        <Route path="/explorer/*" element={<Explorer />} />
        <Route path="/plonky-test" element={<PlonkyTest />} />
        <Route path="/" element={<Landing />} />
      </Routes>
    </BrowserRouter>
  </StrictMode>,
)
