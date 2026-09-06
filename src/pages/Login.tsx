import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

export default function Login() {
  const navigate = useNavigate();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    navigate("/dashboard");
  };

  return (
    <div className="min-h-screen bg-[#080B10] flex flex-col items-center justify-center px-4">
      {/* Background grid */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage: "linear-gradient(rgba(36,43,53,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(36,43,53,0.3) 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      <div className="relative w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center mb-10">
          <div className="w-16 h-16 flex items-center justify-center rounded-xl bg-[#20D3A2]/10 border border-[#20D3A2]/30 mb-5">
            <svg viewBox="0 0 24 24" fill="none" className="w-8 h-8">
              <circle cx="12" cy="12" r="9" stroke="#20D3A2" strokeWidth="1.5" />
              <circle cx="12" cy="12" r="4" stroke="#20D3A2" strokeWidth="1.5" />
              <circle cx="12" cy="12" r="1.5" fill="#20D3A2" />
              <line x1="12" y1="3" x2="12" y2="7" stroke="#20D3A2" strokeWidth="1.5" />
              <line x1="12" y1="17" x2="12" y2="21" stroke="#20D3A2" strokeWidth="1.5" />
              <line x1="3" y1="12" x2="7" y2="12" stroke="#20D3A2" strokeWidth="1.5" />
              <line x1="17" y1="12" x2="21" y2="12" stroke="#20D3A2" strokeWidth="1.5" />
            </svg>
          </div>
          <div className="text-[22px] font-bold text-[#F3F5F7] tracking-wider">ARGUS-ONE</div>
          <div className="text-[11px] text-[#66707D] tracking-widest uppercase mt-1">
            Passive Network Threat Intelligence
          </div>
        </div>

        <div className="bg-[#0D1117] border border-[#242B35] rounded-xl p-8">
          <h2 className="text-[18px] font-semibold text-[#F3F5F7] mb-1">Welcome back</h2>
          <p className="text-[13px] text-[#9AA4B2] mb-6">
            Access the ARGUS-ONE security monitoring console.
          </p>

          <form onSubmit={handleSubmit}>
            <p className="text-sm text-[#9AA4B2] mb-4">Local workspace. Authentication is not configured.</p>
            <button type="submit" className="w-full bg-[#20D3A2] text-[#080B10] font-bold rounded-lg py-2.5">Open dashboard</button>
          </form>

          <div className="mt-6 flex items-center gap-2 justify-center text-[11px] text-[#66707D]">
            <svg viewBox="0 0 16 16" fill="currentColor" className="w-3 h-3">
              <path fillRule="evenodd" d="M8 1a3.5 3.5 0 00-3.5 3.5V6H3a1 1 0 00-1 1v6a1 1 0 001 1h10a1 1 0 001-1V7a1 1 0 00-1-1h-1.5V4.5A3.5 3.5 0 008 1zm2.5 5V4.5a2.5 2.5 0 00-5 0V6h5z" />
            </svg>
            Local access
          </div>
        </div>

        <div className="mt-6 text-center text-[10px] text-[#66707D] uppercase tracking-widest">
          Passive Metadata Analysis · No Payload Inspection
        </div>
      </div>
    </div>
  );
}
