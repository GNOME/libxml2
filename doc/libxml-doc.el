 ;;; libxml-doc.el - look up libxml-symbols and start browser on documentation

;; Author: Felix Natter <fnatter@gmx.net>
;; Created: Jun 21 2000
;; Keywords: libxml documentation

;; 2001-05-31: Adapted by Geert Kloosterman <geertk@ai.rug.nl> 
        
;; This program is free software; you can redistribute it and/or
;; modify it under the terms of the GNU General Public License
;; as published by the Free Software Foundation; either version 2
;; of the License, or (at your option) any later version.
;; 
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;; 
;; You should have received a copy of the GNU General Public License
;; along with this program; if not, write to the Free Software
;; Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

 ;;; Commentary / README

;; these functions allow you to browse the libxml documentation
;; (using lynx within emacs by default; 
;; ----- Installing
;; 1. add the following to ~/.emacs (adapt path and remove comments !)
;; (load ~/elisp/libxml-doc.el)
;; you can also load this conditionally in a c-mode-hook (preferred)
;;
;;(add-hook 'c-mode-hook (lambda()
;;                         (load-file "~/elisp/libxml-doc.el")))
;;
;; or you can use this if you are using libxml2
;;(add-hook 'c-mode-hook (lambda()
;;                         (save-excursion
;;                           (if (search-forward "#include <libxml/" nil t nil)
;;                               (load-file "~/elisp/libxml-doc.el"))
;;                           )))
;;
;; 2. adapt libxmldoc-root:
;; i.e. (setq libxmldoc-root "~/libxml2-2.0.0/doc/html/")
;; 3. change the filter-regex: by default, cpp-defines, callbacks and
;; html-functions are excluded (C-h v libxmldoc-filter-regexp)
;; 4. consider customizing libxmldoc-browse-url (lynx by default);
;; cannot use Emacs/W3 4.0pre46 because it has problems with the html
;; ----- Using
;; call M-x libxmldoc-lookup-symbol: this will prompt with completion
;; and then open the browser showing the documentation. If the word
;; around the point matches a symbol, that is used instead (no completion).

 ;;; ChangeLog:
;; Wed Jun 21 01:07:12 2000: initial release
;; Wed Jun 21 01:45:29 2000: added libxmldoc-lookup-symbol-at-point
;; Wed Jun 21 23:37:58 2000: libxmldoc-lookup-symbol now uses
;; (thing-at-point 'word) if it matches a symbol
;; Thu Jun 22 02:37:46 2000: filtering is only done for completion
;; Thu Jun 22 21:03:41 2000: libxmldoc-browse-url can be customized

;; Thu May 31 2001 (Geert): 
;;       - Changed the `gnome-xml-' html file prefix into `libxml-'.
;;       - Changed the 'word match from thing-at-point into 'symbol.
;;         With 'word, identifiers with an underscore (e.g. BAD_CAST)
;;         don't get matched.

;; Sat Jun 02 2001 (Geert): 
;;       - Cleaned up URI construction: no extraneous '/' in the URI when 
;;         `libxmldoc-root' ends with a '/'.
;;       - Now keeps the list of symbols between calls to speed things up.
;;         Every filter gets it's own list of symbols.  This way it's 
;;         possible to use different values of `libxmldoc-filter-regexp' in
;;         different buffers.
;;       - Fixed symbols for function pointers: now skips '*' when
;;         fetching identifiers from the html files.

;;; TODO:
;; use command-execute for libxml-browse-url

 ;;; Code:

(defvar libxmldoc-root "~/libxml/www.xmlsoft.org"
  "The root-directory of the libxml2-documentation (~ will be expanded).")
(defvar libxmldoc-filter-regexp "^html\\|^\\*\\|^[A-Z_]+\\|^$"
  "Symbols that match this regular expression will be excluded when doing
completion.
 For example:
   callbacks:     \"^\\\\*\" 
   cpp-defines:   \"[A-Z_]+\"
   xml-functions  \"^xml\"
   html-functions \"^html\"
   sax-functions  \".*SAX\"
 By default, callbacks, cpp-defines and html* are excluded. If you redefine
 this, you should include \"^$\" as alternative, which removes empty
 tokens. i.e. removing \"^html\\\\|\" from the above regexp causes html* to
 be shown.")
(defvar libxmldoc-browse-url 'browse-url-lynx-emacs
  "Browser used for browsing documentation. Emacs/W3 4.0pre46 cannot handle
the html, so lynx-emacs is used by default.")
(defvar libxmldoc-symbol-history nil
  "History for looking up libxml-symbols.")

;; GJK: Keep the results from libxmldoc-get-list-of-symbols between
;; calls to speed things up.
(defvar libxmldoc-symbols-alist nil 
  "Alist which stores a symbol list for each `libxmldoc-filter-regexp'. The
never matching regex \"$^\" is used as key when no filtering is needed.") 

 ;;;; public functions

(defun libxmldoc-lookup-symbol(&optional symbol)
  "Look up xml-symbol." (interactive)
  (let ((symbols)
        (real-symbol symbol)
        (url)
        ;; We don't want filtering when there's a symbol specified.
        ;; Use the never matching regex "$^" as a key when using no filter.
        (filter (if symbol "$^" libxmldoc-filter-regexp))
        (no-filter (if symbol t nil)))
  
    ;; Build up a symbol list if neccesary.
    (if (not (assoc filter libxmldoc-symbols-alist))
        (add-to-list 'libxmldoc-symbols-alist
                     (cons filter 
                           (libxmldoc-get-list-of-symbols no-filter))))

    ;; Use the appropriate symbol list.
    (setq symbols (cdr (assoc filter libxmldoc-symbols-alist)))

    (if (null real-symbol)
        (if (assoc (thing-at-point 'symbol) symbols)
            (setq real-symbol (thing-at-point 'symbol))
          (setq real-symbol (completing-read "Libxml: " symbols nil t ""
                                             'libxmldoc-symbol-history "" t))))
    (if (null (assoc real-symbol symbols))
        (error (concat "libxmldoc: '" real-symbol "' not found !")))
    (setq url (cdr (assoc real-symbol symbols)))
;;  (minibuffer-message uri)
    (apply libxmldoc-browse-url (list url))))

;;(defun libxmldoc-lookup-symbol-at-point()
;;  "Look up libxml-symbol at point." (interactive)
;;  (libxmldoc-lookup-symbol (thing-at-point 'word)))

;;;; internal

(defun libxmldoc-get-list-of-symbols(&optional nofilter)
  "Get the list of html-links in the libxml-documentation."
  (let ((files (directory-files libxmldoc-root t
                                "^libxml-.*\\.html$" t))
        (symbols ())
        (case-fold-search t)
        (symbol)
        (uri))
;;  (minibuffer-message "collecting libxml-symbols...")
    (while (car files)
      (find-file (car files))
      (while (re-search-forward
              "<a[^>]*href[ \t\n]*=[ \t\n]*\"\\([^=>]*\\)\"[^>]*>" nil t nil)
        (setq uri (concat "file://" 
                          (expand-file-name (match-string 1) 
                                            libxmldoc-root)))
        (if (not (re-search-forward "\\([^<]*\\)<" nil t nil)) ; GJK: no '*'
            (error "regexp error while finding libxml-symbols.."))
        (setq symbol (match-string 1))
        (setq case-fold-search nil)
        (if (or nofilter
                (null (string-match libxmldoc-filter-regexp symbol)))
            (add-to-list 'symbols (cons symbol uri)))
        (setq case-fold-search t)
        )
      (kill-buffer (current-buffer))
      (setq files (cdr files)))
    symbols))

;;; libxml-doc.el ends here

;;; Local Variables:
;;; indent-tabs-mode: nil
;;; End:
