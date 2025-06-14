import React from 'react';
import { motion } from 'framer-motion';
import { Radar } from 'lucide-react';

const LoadingOverlay = ({ isDark }) => {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-40 flex items-center justify-center backdrop-blur-sm"
    >
      <motion.div
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.8, opacity: 0 }}
        className={`p-8 rounded-3xl backdrop-blur-xl border ${
          isDark 
            ? 'bg-white/10 border-white/20' 
            : 'bg-white/40 border-white/60'
        } shadow-2xl text-center`}
      >
        <motion.div
          animate={{ 
            scale: [1, 1.2, 1],
            rotate: [0, 180, 360]
          }}
          transition={{ 
            duration: 2,
            repeat: Infinity,
            ease: "easeInOut"
          }}
          className="w-16 h-16 mx-auto mb-4"
        >
          <Radar className={`w-full h-full ${isDark ? 'text-purple-400' : 'text-purple-600'}`} />
        </motion.div>
        
        <h3 className={`text-xl font-semibold mb-2 ${isDark ? 'text-white' : 'text-gray-800'}`}>
          Scanning in Progress
        </h3>
        
        <div className="space-y-2">
          {['Analyzing SSL/TLS configuration...', 'Checking security headers...', 'Testing for vulnerabilities...'].map((text, index) => (
            <motion.p
              key={index}
              initial={{ opacity: 0 }}
              animate={{ opacity: [0, 1, 0] }}
              transition={{ 
                duration: 1.5,
                delay: index * 0.5,
                repeat: Infinity
              }}
              className={`text-sm ${isDark ? 'text-gray-300' : 'text-gray-600'}`}
            >
              {text}
            </motion.p>
          ))}
        </div>
        
        {/* Ripple Effect */}
        <div className="relative mt-6">
          {[0, 1, 2].map((i) => (
            <motion.div
              key={i}
              animate={{
                scale: [0, 2, 0],
                opacity: [1, 0.5, 0]
              }}
              transition={{
                duration: 2,
                delay: i * 0.3,
                repeat: Infinity,
                ease: "easeOut"
              }}
              className={`absolute inset-0 rounded-full border-2 ${
                isDark ? 'border-purple-400' : 'border-purple-600'
              }`}
              style={{
                width: '60px',
                height: '60px',
                left: '50%',
                top: '50%',
                transform: 'translate(-50%, -50%)'
              }}
            />
          ))}
        </div>
      </motion.div>
    </motion.div>
  );
};

export default LoadingOverlay;