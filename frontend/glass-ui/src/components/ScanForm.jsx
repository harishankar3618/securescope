import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Radar } from 'lucide-react';

const ScanForm = ({ onScan, isScanning, isDark }) => {
  const [url, setUrl] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url.trim() && !isScanning) {
      onScan(url.trim());
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className={`p-8 rounded-3xl backdrop-blur-xl border ${
        isDark 
          ? 'bg-white/10 border-white/20' 
          : 'bg-white/40 border-white/60'
      } shadow-2xl`}
    >
      <form onSubmit={handleSubmit} className="space-y-6">
        <div>
          <label className={`block text-sm font-medium mb-2 ${
            isDark ? 'text-gray-200' : 'text-gray-700'
          }`}>
            Target URL
          </label>
          <motion.input
            whileFocus={{ scale: 1.02 }}
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className={`w-full px-4 py-3 rounded-xl backdrop-blur-sm border ${
              isDark 
                ? 'bg-white/5 border-white/20 text-white placeholder-gray-400' 
                : 'bg-white/50 border-white/40 text-gray-800 placeholder-gray-500'
            } focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-200`}
            disabled={isScanning}
          />
        </div>
        
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          type="submit"
          disabled={isScanning || !url.trim()}
          className={`w-full py-4 px-6 rounded-xl font-semibold text-white bg-gradient-to-r ${
            isScanning || !url.trim()
              ? 'from-gray-500 to-gray-600 cursor-not-allowed'
              : 'from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600'
          } transition-all duration-300 shadow-lg hover:shadow-xl disabled:opacity-50`}
        >
          <div className="flex items-center justify-center space-x-2">
            {isScanning ? (
              <>
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                  className="w-5 h-5 border-2 border-white border-t-transparent rounded-full"
                />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <Radar className="w-5 h-5" />
                <span>Initiate Scan</span>
              </>
            )}
          </div>
        </motion.button>
      </form>
    </motion.div>
  );
};

export default ScanForm;