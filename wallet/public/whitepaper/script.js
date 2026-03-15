// Trust Stack Network - Whitepaper Interactive Features

document.addEventListener('DOMContentLoaded', function() {
    // Initialize Mermaid diagrams
    if (typeof mermaid !== 'undefined') {
        mermaid.initialize({
            startOnLoad: true,
            theme: 'default',
            fontFamily: 'Inter, sans-serif',
            fontSize: 14,
            securityLevel: 'loose',
            flowchart: {
                useMaxWidth: true,
                htmlLabels: true,
                curve: 'basis'
            }
        });
    }

    // Smooth scrolling for navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Active section highlighting in table of contents
    function updateActiveTocItem() {
        const sections = document.querySelectorAll('.section');
        const tocLinks = document.querySelectorAll('.toc a');

        let current = '';
        const scrollPosition = window.scrollY + 150; // Offset for fixed header

        sections.forEach(section => {
            const sectionTop = section.offsetTop;
            const sectionHeight = section.offsetHeight;

            if (scrollPosition >= sectionTop && scrollPosition < sectionTop + sectionHeight) {
                current = section.getAttribute('id');
            }
        });

        tocLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === '#' + current) {
                link.classList.add('active');
            }
        });
    }

    // Throttled scroll listener for performance
    let scrollTimeout;
    window.addEventListener('scroll', () => {
        if (scrollTimeout) {
            clearTimeout(scrollTimeout);
        }
        scrollTimeout = setTimeout(updateActiveTocItem, 50);
    });

    // Initial call to set active state
    updateActiveTocItem();

    // Copy code functionality
    document.querySelectorAll('.code-block, code').forEach(codeElement => {
        const isInlineCode = codeElement.tagName.toLowerCase() === 'code';

        if (!isInlineCode && codeElement.parentElement.className !== 'feature-card') {
            codeElement.style.position = 'relative';

            const copyButton = document.createElement('button');
            copyButton.className = 'copy-button';
            copyButton.innerHTML = '📋';
            copyButton.title = 'Copy code';
            copyButton.style.cssText = `
                position: absolute;
                top: 10px;
                right: 10px;
                background: var(--bg-primary);
                border: 1px solid var(--border-color);
                border-radius: 4px;
                padding: 5px 8px;
                cursor: pointer;
                font-size: 14px;
                opacity: 0.7;
                transition: opacity 0.2s ease;
            `;

            copyButton.addEventListener('click', () => {
                const textToCopy = codeElement.textContent || codeElement.innerText;
                navigator.clipboard.writeText(textToCopy).then(() => {
                    copyButton.innerHTML = '✅';
                    setTimeout(() => {
                        copyButton.innerHTML = '📋';
                    }, 2000);
                }).catch(() => {
                    // Fallback for older browsers
                    const textArea = document.createElement('textarea');
                    textArea.value = textToCopy;
                    document.body.appendChild(textArea);
                    textArea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textArea);

                    copyButton.innerHTML = '✅';
                    setTimeout(() => {
                        copyButton.innerHTML = '📋';
                    }, 2000);
                });
            });

            copyButton.addEventListener('mouseenter', () => {
                copyButton.style.opacity = '1';
            });

            copyButton.addEventListener('mouseleave', () => {
                copyButton.style.opacity = '0.7';
            });

            codeElement.appendChild(copyButton);
        }
    });

    // Table responsive wrapper
    document.querySelectorAll('table').forEach(table => {
        if (!table.closest('.table-container')) {
            const wrapper = document.createElement('div');
            wrapper.className = 'table-container';
            table.parentNode.insertBefore(wrapper, table);
            wrapper.appendChild(table);
        }
    });

    // Feature cards hover effects
    document.querySelectorAll('.feature-card, .roadmap-item').forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-4px)';
        });

        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(-2px)';
        });
    });

    // Search functionality (basic)
    function addSearchToToc() {
        const toc = document.querySelector('.toc');
        if (!toc) return;

        const searchInput = document.createElement('input');
        searchInput.type = 'text';
        searchInput.placeholder = 'Rechercher dans le document...';
        searchInput.style.cssText = `
            width: 100%;
            padding: 8px 12px;
            margin-bottom: 1rem;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 14px;
            background: var(--bg-primary);
        `;

        const tocTitle = toc.querySelector('h3');
        tocTitle.after(searchInput);

        const tocLinks = Array.from(toc.querySelectorAll('a'));

        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();

            tocLinks.forEach(link => {
                const text = link.textContent.toLowerCase();
                const listItem = link.parentElement;

                if (text.includes(searchTerm) || searchTerm === '') {
                    listItem.style.display = 'block';
                } else {
                    listItem.style.display = 'none';
                }
            });
        });
    }

    addSearchToToc();

    // Dark mode toggle (optional enhancement)
    function addDarkModeToggle() {
        const navbar = document.querySelector('.navbar .nav-container');
        if (!navbar) return;

        const darkModeToggle = document.createElement('button');
        darkModeToggle.innerHTML = '🌙';
        darkModeToggle.title = 'Toggle dark mode';
        darkModeToggle.style.cssText = `
            background: none;
            border: none;
            font-size: 1.2rem;
            cursor: pointer;
            padding: 8px;
            border-radius: 6px;
            transition: background 0.2s ease;
        `;

        darkModeToggle.addEventListener('click', () => {
            document.body.classList.toggle('dark-mode');
            const isDark = document.body.classList.contains('dark-mode');
            darkModeToggle.innerHTML = isDark ? '☀️' : '🌙';

            // Store preference
            localStorage.setItem('darkMode', isDark);
        });

        // Check stored preference
        const savedDarkMode = localStorage.getItem('darkMode') === 'true';
        if (savedDarkMode) {
            document.body.classList.add('dark-mode');
            darkModeToggle.innerHTML = '☀️';
        }

        navbar.appendChild(darkModeToggle);
    }

    // Performance monitoring
    if (typeof performance !== 'undefined' && performance.mark) {
        performance.mark('whitepaper-interactive-loaded');
    }

    console.log('TSN Whitepaper v0.1 - Interactive features loaded');
});

// Lazy loading for better performance
if ('IntersectionObserver' in window) {
    const imageObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const img = entry.target;
                if (img.dataset.src) {
                    img.src = img.dataset.src;
                    img.removeAttribute('data-src');
                    imageObserver.unobserve(img);
                }
            }
        });
    });

    document.querySelectorAll('img[data-src]').forEach(img => {
        imageObserver.observe(img);
    });
}

// Error handling for Mermaid diagrams
window.addEventListener('error', function(e) {
    if (e.message && e.message.includes('mermaid')) {
        console.warn('Mermaid diagram failed to render:', e.message);
        // Optionally show fallback text for diagrams
        document.querySelectorAll('.mermaid').forEach(diagram => {
            if (diagram.innerHTML.includes('graph') || diagram.innerHTML.includes('sequenceDiagram')) {
                const fallback = document.createElement('div');
                fallback.style.cssText = `
                    padding: 2rem;
                    text-align: center;
                    color: var(--text-muted);
                    font-style: italic;
                `;
                fallback.textContent = 'Diagramme interactif (nécessite JavaScript)';
                diagram.parentNode.replaceChild(fallback, diagram);
            }
        });
    }
});

// Export function for potential future use
window.TSNWhitepaper = {
    version: '0.1.0',
    scrollToSection: function(sectionId) {
        const section = document.getElementById(sectionId);
        if (section) {
            section.scrollIntoView({ behavior: 'smooth' });
        }
    },

    printDocument: function() {
        window.print();
    },

    exportToPDF: function() {
        // This would require additional PDF generation library
        console.log('PDF export functionality would be implemented here');
    }
};