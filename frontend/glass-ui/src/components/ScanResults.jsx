import React from 'react';
import { motion } from 'framer-motion';

const ScanResults = ({ results, isDark }) => {
  const getSeverityColor = (severity) => {
    const colors = {
      critical: isDark ? 'from-red-500 to-red-600' : 'from-red-600 to-red-700',
      high: isDark ? 'from-orange-500 to-orange-600' : 'from-orange-600 to-orange-700',
      medium: isDark ? 'from-yellow-500 to-yellow-600' : 'from-yellow-600 to-yellow-700',
      low: isDark ? 'from-blue-500 to-blue-600' : 'from-blue-600 to-blue-700',
      info: isDark ? 'from-gray-500 to-gray-600' : 'from-gray-600 to-gray-700'
    };
    return colors[severity?.toLowerCase()] || colors.info;
  };

  const getSeverityGlow = (severity) => {
    const glows = {
      critical: 'shadow-red-500/50',
      high: 'shadow-orange-500/50',
      medium: 'shadow-yellow-500/50',
      low: 'shadow-blue-500/50',
      info: 'shadow-gray-500/50'
    };
    return glows[severity?.toLowerCase()] || glows.info;
  };

  if (results.error) {
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        className={`p-8 rounded-3xl backdrop-blur-xl border ${
          isDark 
            ? 'bg-red-500/10 border-red-500/30' 
            : 'bg-red-100/50 border-red-300/50'
        } shadow-2xl mt-8`}
      >
        <div className="flex items-center space-x-3">
          <div className="w-12 h-12 rounded-full bg-gradient-to-r from-red-500 to-red-600 flex items-center justify-center">
            <span className="text-white font-bold">!</span>
          </div>
          <div>
            <h3 className={`text-xl font-semibold ${isDark ? 'text-white' : 'text-gray-800'}`}>
              Scan Error
            </h3>
            <p className={`${isDark ? 'text-red-300' : 'text-red-600'}`}>
              {results.error}
            </p>
          </div>
        </div>
      </motion.div>
    );
  }

  return (
    <div className="space-y-8 mt-8">
      {/* Summary Card */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className={`p-8 rounded-3xl backdrop-blur-xl border ${
          isDark 
            ? 'bg-white/10 border-white/20' 
            : 'bg-white/40 border-white/60'
        } shadow-2xl`}
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className={`text-2xl font-bold ${isDark ? 'text-white' : 'text-gray-800'}`}>
            Scan Results
          </h2>
          <motion.div
            animate={{ 
              boxShadow: ['0 0 0 0 rgba(168, 85, 247, 0.4)', '0 0 0 10px rgba(168, 85, 247, 0)', '0 0 0 0 rgba(168, 85, 247, 0)']
            }}
            transition={{ duration: 2, repeat: Infinity }}
            className="w-3 h-3 bg-purple-500 rounded-full"
          />
        </div>
        
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {Object.entries(results.summary || {}).map(([key, value]) => {
            if (key === 'total_issues') return null;
            return (
              <motion.div
                key={key}
                whileHover={{ scale: 1.05 }}
                className={`p-4 rounded-xl bg-gradient-to-r ${getSeverityColor(key)} ${getSeverityGlow(key)} shadow-lg`}
              >
                <div className="text-center">
                  <div className="text-2xl font-bold text-white">{value}</div>
                  <div className="text-sm text-white/80 capitalize">{key}</div>
                </div>
              </motion.div>
            );
          })}
        </div>

        {/* URL and Timestamp */}
        <div className="mt-6 pt-6 border-t border-white/20">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between space-y-2 md:space-y-0">
            <div>
              <p className={`text-sm ${isDark ? 'text-gray-400' : 'text-gray-600'}`}>
                Target URL
              </p>
              <p className={`font-mono text-sm ${isDark ? 'text-purple-300' : 'text-purple-600'}`}>
                {results.url}
              </p>
            </div>
            {results.timestamp && (
              <div>
                <p className={`text-sm ${isDark ? 'text-gray-400' : 'text-gray-600'}`}>
                  Scanned at
                </p>
                <p className={`text-sm ${isDark ? 'text-gray-300' : 'text-gray-700'}`}>
                  {new Date(results.timestamp).toLocaleString()}
                </p>
              </div>
            )}
          </div>
        </div>
      </motion.div>

      {/* Vulnerabilities List */}
      {results.vulnerabilities && results.vulnerabilities.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="space-y-4"
        >
          <h3 className={`text-xl font-semibold ${isDark ? 'text-white' : 'text-gray-800'}`}>
            Detected Vulnerabilities
          </h3>
          
          {results.vulnerabilities.map((vuln, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.1 }}
              whileHover={{ scale: 1.02 }}
              className={`p-6 rounded-2xl backdrop-blur-xl border ${
                isDark 
                  ? 'bg-white/5 border-white/10' 
                  : 'bg-white/30 border-white/40'
              } shadow-lg hover:shadow-xl transition-all duration-300`}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <span className={`px-3 py-1 rounded-full text-xs font-semibold text-white bg-gradient-to-r ${getSeverityColor(vuln.severity)} ${getSeverityGlow(vuln.severity)} shadow-lg`}>
                      {vuln.severity?.toUpperCase() || 'INFO'}
                    </span>
                    <h4 className={`font-semibold ${isDark ? 'text-white' : 'text-gray-800'}`}>
                      {vuln.title || vuln.type || 'Security Issue'}
                    </h4>
                  </div>
                  <p className={`text-sm ${isDark ? 'text-gray-300' : 'text-gray-600'} mb-3`}>
                    {vuln.description || 'No description available'}
                  </p>
                  {vuln.recommendation && (
                    <div className={`p-3 rounded-lg ${
                      isDark ? 'bg-white/5' : 'bg-white/50'
                    }`}>
                      <p className={`text-sm font-medium ${isDark ? 'text-purple-300' : 'text-purple-600'}`}>
                        Recommendation: {vuln.recommendation}
                      </p>
                    </div>
                  )}
                  {vuln.references && vuln.references.length > 0 && (
                    <div className="mt-3">
                      <p className={`text-xs ${isDark ? 'text-gray-400' : 'text-gray-500'} mb-1`}>
                        References:
                      </p>
                      <div className="flex flex-wrap gap-2">
                        {vuln.references.map((ref, refIndex) => (
                          <a
                            key={refIndex}
                            href={ref}
                            target="_blank"
                            rel="noopener noreferrer"
                            className={`text-xs px-2 py-1 rounded ${
                              isDark 
                                ? 'bg-purple-500/20 text-purple-300 hover:bg-purple-500/30' 
                                : 'bg-purple-100 text-purple-600 hover:bg-purple-200'
                            } transition-colors duration-200`}
                          >
                            {ref}
                          </a>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          ))}
        </motion.div>
      )}

      {/* Additional Information */}
      {results.ssl_info && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className={`p-6 rounded-2xl backdrop-blur-xl border ${
            isDark 
              ? 'bg-white/5 border-white/10' 
              : 'bg-white/30 border-white/40'
          } shadow-lg`}
        >
          <h3 className={`text-lg font-semibold mb-4 ${isDark ? 'text-white' : 'text-gray-800'}`}>
            SSL/TLS Information
          </h3>
          <div className="grid md:grid-cols-2 gap-4">
            {Object.entries(results.ssl_info).map(([key, value]) => (
              <div key={key} className="space-y-1">
                <p className={`text-sm font-medium ${isDark ? 'text-gray-300' : 'text-gray-600'}`}>
                  {key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                </p>
                <p className={`text-sm ${isDark ? 'text-white' : 'text-gray-800'}`}>
                  {typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)}
                </p>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* No Vulnerabilities Found */}
      {(!results.vulnerabilities || results.vulnerabilities.length === 0) && !results.error && (
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className={`p-8 rounded-3xl backdrop-blur-xl border ${
            isDark 
              ? 'bg-green-500/10 border-green-500/30' 
              : 'bg-green-100/50 border-green-300/50'
          } shadow-2xl text-center`}
        >
          <motion.div
            animate={{ scale: [1, 1.1, 1] }}
            transition={{ duration: 2, repeat: Infinity }}
            className="w-16 h-16 mx-auto mb-4 bg-gradient-to-r from-green-500 to-green-600 rounded-full flex items-center justify-center"
          >
            <span className="text-white text-2xl">✓</span>
          </motion.div>
          <h3 className={`text-xl font-semibold mb-2 ${isDark ? 'text-white' : 'text-gray-800'}`}>
            No Critical Vulnerabilities Found
          </h3>
          <p className={`${isDark ? 'text-green-300' : 'text-green-600'}`}>
            The target appears to have good security practices in place.
          </p>
        </motion.div>
      )}
    </div>
  );
};

export default ScanResults;