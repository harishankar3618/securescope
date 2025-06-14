import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Radar, Zap, Eye } from 'lucide-react';
import ScanForm from './components/ScanForm';
import LoadingOverlay from './components/LoadingOverlay';
import ScanResults from './components/ScanResults';
import ThemeToggle from './components/ThemeToggle';

const App = () => {
  const [isDark, setIsDark] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [showIntro, setShowIntro] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => setShowIntro(false), 3000);
    return () => clearTimeout(timer);
  }, []);

  const handleScan = async (url) => {
    setIsScanning(true);
    setScanResults(null);
    
    try {
      const response = await fetch('http://localhost:5000/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });
      
      const data = await response.json();
      
      // Simulate realistic scan delay
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      setScanResults(data);
    } catch (error) {
      setScanResults({
        error: 'Failed to connect to scanner service',
        url: url,
        timestamp: new Date().toISOString()
      });
    } finally {
      setIsScanning(false);
    }
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
        delayChildren: 0.3
      }
    }
  };

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
      transition: {
        type: "spring",
        stiffness: 100
      }
    }
  };

  return (
    <div className={`min-h-screen transition-all duration-700 ${
      isDark 
        ? 'bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900' 
        : 'bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50'
    }`}>
      {/* Animated Background Elements */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <motion.div
          animate={{
            rotate: 360,
            scale: [1, 1.1, 1],
          }}
          transition={{
            duration: 20,
            repeat: Infinity,
            ease: "linear"
          }}
          className={`absolute -top-40 -right-40 w-80 h-80 rounded-full blur-3xl opacity-20 ${
            isDark ? 'bg-purple-500' : 'bg-blue-400'
          }`}
        />
        <motion.div
          animate={{
            rotate: -360,
            scale: [1, 1.2, 1],
          }}
          transition={{
            duration: 25,
            repeat: Infinity,
            ease: "linear"
          }}
          className={`absolute -bottom-40 -left-40 w-96 h-96 rounded-full blur-3xl opacity-20 ${
            isDark ? 'bg-blue-500' : 'bg-purple-400'
          }`}
        />
      </div>

      <ThemeToggle isDark={isDark} setIsDark={setIsDark} />

      <AnimatePresence>
        {showIntro && (
          <motion.div
            initial={{ opacity: 1 }}
            exit={{ opacity: 0, scale: 0.8 }}
            transition={{ duration: 0.8 }}
            className="fixed inset-0 z-50 flex items-center justify-center backdrop-blur-sm"
          >
            <motion.div
              initial={{ scale: 0, rotate: -180 }}
              animate={{ scale: 1, rotate: 0 }}
              exit={{ scale: 0, rotate: 180 }}
              transition={{ 
                type: "spring", 
                stiffness: 100,
                damping: 15
              }}
              className={`p-8 rounded-3xl backdrop-blur-xl border ${
                isDark 
                  ? 'bg-white/10 border-white/20' 
                  : 'bg-white/40 border-white/60'
              } shadow-2xl`}
            >
              <div className="flex items-center space-x-4">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                >
                  <Shield className={`w-12 h-12 ${isDark ? 'text-purple-400' : 'text-purple-600'}`} />
                </motion.div>
                <div>
                  <h1 className={`text-2xl font-bold ${isDark ? 'text-white' : 'text-gray-800'}`}>
                    SecureScope
                  </h1>
                  <p className={`${isDark ? 'text-purple-300' : 'text-purple-600'}`}>
                    Advanced Vulnerability Scanner
                  </p>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="container mx-auto px-4 py-8">
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="max-w-4xl mx-auto"
        >
          {/* Header */}
          <motion.div variants={itemVariants} className="text-center mb-12">
            <div className="flex justify-center items-center space-x-3 mb-4">
              <motion.div
                animate={{ 
                  rotate: [0, 360],
                  scale: [1, 1.1, 1]
                }}
                transition={{ 
                  duration: 3,
                  repeat: Infinity,
                  ease: "easeInOut"
                }}
              >
                <Eye className={`w-8 h-8 ${isDark ? 'text-purple-400' : 'text-purple-600'}`} />
              </motion.div>
              <h1 className={`text-4xl font-bold bg-gradient-to-r ${
                isDark 
                  ? 'from-purple-400 to-pink-400' 
                  : 'from-purple-600 to-pink-600'
              } bg-clip-text text-transparent`}>
                SecureScope
              </h1>
              <motion.div
                animate={{ 
                  scale: [1, 1.2, 1],
                  opacity: [0.5, 1, 0.5]
                }}
                transition={{ 
                  duration: 2,
                  repeat: Infinity,
                  ease: "easeInOut"
                }}
              >
                <Radar className={`w-8 h-8 ${isDark ? 'text-pink-400' : 'text-pink-600'}`} />
              </motion.div>
            </div>
            <p className={`text-lg ${isDark ? 'text-gray-300' : 'text-gray-600'}`}>
              Advanced vulnerability scanning through the lens of security
            </p>
          </motion.div>

          {/* Scan Form */}
          <motion.div variants={itemVariants}>
            <ScanForm onScan={handleScan} isScanning={isScanning} isDark={isDark} />
          </motion.div>

          {/* Loading Overlay */}
          <AnimatePresence>
            {isScanning && (
              <LoadingOverlay isDark={isDark} />
            )}
          </AnimatePresence>

          {/* Scan Results */}
          <AnimatePresence>
            {scanResults && !isScanning && (
              <motion.div
                initial={{ opacity: 0, y: 50 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -50 }}
                transition={{ duration: 0.5 }}
                variants={itemVariants}
              >
                <ScanResults results={scanResults} isDark={isDark} />
              </motion.div>
            )}
          </AnimatePresence>

          {/* Feature Cards */}
          {!scanResults && !isScanning && (
            <motion.div 
              variants={containerVariants}
              className="grid md:grid-cols-3 gap-6 mt-16"
            >
              {[
                {
                  icon: Shield,
                  title: "SSL/TLS Analysis",
                  description: "Deep certificate and encryption validation"
                },
                {
                  icon: Zap,
                  title: "Real-time Scanning",
                  description: "Lightning-fast vulnerability detection"
                },
                {
                  icon: Eye,
                  title: "Comprehensive Reports",
                  description: "Detailed security insights and recommendations"
                }
              ].map((feature, index) => (
                <motion.div
                  key={index}
                  variants={itemVariants}
                  whileHover={{ scale: 1.05, y: -5 }}
                  className={`p-6 rounded-2xl backdrop-blur-xl border ${
                    isDark 
                      ? 'bg-white/5 border-white/10 hover:bg-white/10' 
                      : 'bg-white/30 border-white/40 hover:bg-white/50'
                  } transition-all duration-300 shadow-lg hover:shadow-xl`}
                >
                  <feature.icon className={`w-12 h-12 mb-4 ${
                    isDark ? 'text-purple-400' : 'text-purple-600'
                  }`} />
                  <h3 className={`text-xl font-semibold mb-2 ${
                    isDark ? 'text-white' : 'text-gray-800'
                  }`}>
                    {feature.title}
                  </h3>
                  <p className={`${isDark ? 'text-gray-300' : 'text-gray-600'}`}>
                    {feature.description}
                  </p>
                </motion.div>
              ))}
            </motion.div>
          )}
        </motion.div>
      </div>
    </div>
  );
};

export default App;