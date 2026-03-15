import { motion } from 'framer-motion'
import { ReactNode } from 'react'

interface AnimatedButtonProps {
  children: ReactNode
  variant?: 'primary' | 'secondary'
  onClick?: () => void
  className?: string
  disabled?: boolean
}

export const AnimatedButton = ({
  children,
  variant = 'primary',
  onClick,
  className = '',
  disabled = false,
  ...props
}: AnimatedButtonProps) => {
  const buttonVariants = {
    idle: {
      scale: 1,
      y: 0,
      boxShadow: variant === 'primary'
        ? '0 4px 16px rgba(88, 166, 255, 0.4)'
        : '0 2px 8px rgba(0, 0, 0, 0.1)'
    },
    hover: {
      scale: 1.02,
      y: -2,
      boxShadow: variant === 'primary'
        ? '0 8px 25px rgba(88, 166, 255, 0.6)'
        : '0 4px 16px rgba(88, 166, 255, 0.3)',
      transition: {
        type: "spring",
        stiffness: 400,
        damping: 10
      }
    },
    tap: {
      scale: 0.98,
      y: 0,
      transition: {
        type: "spring",
        stiffness: 500,
        damping: 15
      }
    }
  }

  const baseClasses = `nav-link ${variant === 'secondary' ? 'secondary' : ''} ${className}`

  return (
    <motion.button
      variants={buttonVariants}
      initial="idle"
      whileHover={!disabled ? "hover" : undefined}
      whileTap={!disabled ? "tap" : undefined}
      className={baseClasses}
      onClick={onClick}
      disabled={disabled}
      style={{
        border: 'none',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.6 : 1
      }}
      {...props}
    >
      {children}
    </motion.button>
  )
}