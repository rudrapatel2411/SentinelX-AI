"use client";

import React, { useState, useRef } from "react";
import { UploadCloud, FileText, AlertCircle, FileCode, CheckCircle2 } from "lucide-react";

interface FileDropzoneProps {
  onFileSelected: (file: File) => void;
  disabled?: boolean;
}

export const FileDropzone: React.FC<FileDropzoneProps> = ({
  onFileSelected,
  disabled = false,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const validateAndSelect = (file: File) => {
    setErrorMsg(null);
    const MAX_SIZE = 50 * 1024 * 1024;
    if (file.size > MAX_SIZE) {
      setErrorMsg("File exceeds 50MB maximum upload limit.");
      return;
    }
    setSelectedFile(file);
    onFileSelected(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (disabled) return;
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSelect(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      validateAndSelect(e.target.files[0]);
    }
  };

  // Quick Synthetic Test Samples
  const handleLoadTestSample = (sampleType: "eicar" | "clean_pdf" | "spoofed_exe") => {
    let blob: Blob;
    let fileName: string;

    if (sampleType === "eicar") {
      const eicarString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
      blob = new Blob([eicarString], { type: "text/plain" });
      fileName = "eicar-standard-antivirus-test.com";
    } else if (sampleType === "spoofed_exe") {
      // Mock executable buffer with MZ header and PE signature
      const buf = new Uint8Array(512);
      buf[0] = 0x4d; // 'M'
      buf[1] = 0x5a; // 'Z'
      buf[0x3c] = 0x80; // PE offset
      buf[0x80] = 0x50; // 'P'
      buf[0x81] = 0x45; // 'E'
      blob = new Blob([buf], { type: "application/pdf" });
      fileName = "invoice_2026_receipt.pdf";
    } else {
      const pdfContent = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF";
      blob = new Blob([pdfContent], { type: "application/pdf" });
      fileName = "sample_clean_document.pdf";
    }

    const testFile = new File([blob], fileName);
    validateAndSelect(testFile);
  };

  return (
    <div className="space-y-4">
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => !disabled && fileInputRef.current?.click()}
        className={`border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all ${
          dragActive
            ? "border-cyan-400 bg-cyan-950/20 shadow-cyan-glow"
            : selectedFile
            ? "border-emerald-500/50 bg-emerald-950/10"
            : "border-slate-800 hover:border-slate-700 bg-slate-950/40 hover:bg-slate-900/30"
        } ${disabled ? "opacity-50 cursor-not-allowed" : ""}`}
      >
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={handleChange}
          disabled={disabled}
        />

        <div className="flex flex-col items-center justify-center space-y-3">
          <div
            className={`w-14 h-14 rounded-2xl flex items-center justify-center border ${
              selectedFile
                ? "bg-emerald-950/60 border-emerald-500/50 text-emerald-400"
                : "bg-slate-900 border-slate-800 text-cyan-400"
            }`}
          >
            {selectedFile ? (
              <CheckCircle2 className="w-7 h-7" />
            ) : (
              <UploadCloud className="w-7 h-7" />
            )}
          </div>

          {selectedFile ? (
            <div className="space-y-1">
              <p className="text-sm font-bold text-slate-100 flex items-center justify-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span>{selectedFile.name}</span>
              </p>
              <p className="text-xs text-slate-400 font-mono">
                {(selectedFile.size / 1024).toFixed(1)} KB — Ready for SentinelX Inspection
              </p>
            </div>
          ) : (
            <div className="space-y-1">
              <p className="text-sm font-bold text-slate-200">
                Drag & Drop your suspicious file here, or <span className="text-cyan-400">Browse</span>
              </p>
              <p className="text-xs text-slate-500">
                Supports PDF, DOCX, XLSX, PPTX, ZIP, EXE, APK, PNG, JPG, TXT (Max 50MB)
              </p>
            </div>
          )}
        </div>
      </div>

      {errorMsg && (
        <div className="p-3 rounded-lg bg-rose-950/50 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Quick Test Artifacts */}
      <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
        <span className="text-slate-500 flex items-center gap-1">
          <FileCode className="w-3.5 h-3.5" />
          Test Samples:
        </span>
        <button
          type="button"
          onClick={() => handleLoadTestSample("eicar")}
          disabled={disabled}
          className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-rose-400 border border-rose-900/40 text-[11px] font-mono transition-colors"
        >
          EICAR Antivirus Test File
        </button>
        <button
          type="button"
          onClick={() => handleLoadTestSample("spoofed_exe")}
          disabled={disabled}
          className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-amber-400 border border-amber-900/40 text-[11px] font-mono transition-colors"
        >
          Spoofed Extension (EXE disguised as PDF)
        </button>
        <button
          type="button"
          onClick={() => handleLoadTestSample("clean_pdf")}
          disabled={disabled}
          className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-emerald-400 border border-emerald-900/40 text-[11px] font-mono transition-colors"
        >
          Clean PDF Sample
        </button>
      </div>
    </div>
  );
};
