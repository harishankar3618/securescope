import React from 'react';
import { motion } from 'framer-motion';

const ThemeToggle = ({ isDark, setIsDark }) => {
  return (
    <motion.button
      whileHover={{ scale: 1.1 }}
      whileTap={{ scale: 0.9 }}
      onClick={() => setIsDark(!isDark)}
      className={`fixed top-6 right-6 z-30 p-3 rounded-full backdrop-blur-xl border ${
        isDark 
          ? 'bg-white/10 border-white/20 text-white' 
          : 'bg-white/40 border-white/60 text-gray-800'
      } shadow-lg hover:shadow-xl transition-all duration-300`}
    >
      <motion.div
        animate={{ rotate: isDark ? 180 : 0 }}
        transition={{ duration: 0.5 }}
      >
        {isDark ? (
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            className="w-6 h-6 bg-yellow-400 rounded-full shadow-lg"
          />
        ) : (
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            className="w-6 h-6 bg-slate-700 rounded-full shadow-lg relative overflow-hidden"
          >
            <div className="absolute top-1 right-1 w-2 h-2 bg-slate-300 rounded-full" />
            <div className="absolute bottom-1 left-1 w-1 h-1 bg-slate-400 rounded-full" />
          </motion.div>
        )}
      </motion.div>
    </motion.button>
  );
};

export default ThemeToggle;