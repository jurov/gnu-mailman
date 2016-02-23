import signal
import cgi
import time

from Mailman import mm_cfg
from Mailman import Errors
from Mailman import i18n
from Mailman import MailList
from Mailman import Site
from Mailman.Utils import unique_message_id,report_submission
from Mailman.htmlformat import *
from Mailman.Logging.Syslog import syslog
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.image import MIMEImage
from email.mime.audio import MIMEAudio
from email.Utils import formatdate
from email.header import Header
from Mailman import Post

from email import Message
import os

# Set up i18n
_ = i18n._
i18n.set_language(mm_cfg.DEFAULT_SERVER_LANGUAGE)

def post_overview(msg=''):
    # Present the general listinfo overview
    hostname = Utils.get_domain()
    # Set up the document and assign it the correct language.  The only one we
    # know about at the moment is the server's default.
    doc = Document()
    doc.set_language(mm_cfg.DEFAULT_SERVER_LANGUAGE)

    legend = _("%(hostname)s Mailing Lists")
    doc.SetTitle(legend)

    table = Table(border=0, width="100%")
    table.AddRow([Center(Header(2, legend))])
    table.AddCellInfo(table.GetCurrentRowIndex(), 0, colspan=2,
                      bgcolor=mm_cfg.WEB_HEADER_COLOR)

    # Skip any mailing lists that isn't advertised.
    advertised = []
    listnames = Utils.list_names()
    listnames.sort()

    for name in listnames:
        mlist = MailList.MailList(name, lock=0)
        if mlist.advertised:
            if mm_cfg.VIRTUAL_HOST_OVERVIEW and (
                   mlist.web_page_url.find('/%s/' % hostname) == -1 and
                   mlist.web_page_url.find('/%s:' % hostname) == -1):
                # List is for different identity of this host - skip it.
                continue
            else:
                advertised.append((mlist.GetScriptURL('post'),
                                   mlist.real_name,
                                   Utils.websafe(mlist.description)))
    if msg:
        greeting = FontAttr(msg, color="ff5060", size="+1")
    else:
        greeting = FontAttr(_('Welcome!'), size='+2')

    welcome = [greeting]
    mailmanlink = Link(mm_cfg.MAILMAN_URL, _('Mailman')).Format()
    if not advertised:
        welcome.extend(
            _('''<p>There currently are no publicly-advertised
            %(mailmanlink)s mailing lists on %(hostname)s.'''))
    else:
        welcome.append(
            _('''<p>Below is a listing of all the public mailing lists on
            %(hostname)s. Click on one to post a message to.'''))

    table.AddRow([apply(Container, welcome)])
    table.AddCellInfo(max(table.GetCurrentRowIndex(), 0), 0, colspan=2)

    if advertised:
        table.AddRow(['&nbsp;', '&nbsp;'])
        table.AddRow([Bold(FontAttr(_('List'), size='+2')),
                      Bold(FontAttr(_('Description'), size='+2'))
                      ])
        highlight = 1
        for url, real_name, description in advertised:
            table.AddRow(
                [Link(url, Bold(real_name)),
                      description or Italic(_('[no description available]'))])
            if highlight and mm_cfg.WEB_HIGHLIGHT_COLOR:
                table.AddRowInfo(table.GetCurrentRowIndex(),
                                 bgcolor=mm_cfg.WEB_HIGHLIGHT_COLOR)
            highlight = not highlight

    doc.AddItem(table)
    doc.AddItem('<hr>')
    doc.AddItem(MailmanLogo())
    print doc.Format()

def showpost(mlist, lang, message = ''):
    doc = HeadlessDocument()
    doc.set_language(lang)

    replacements = mlist.GetStandardReplacements(lang)
    replacements['<mm-post-form-start>'] = mlist.FormatFormStart(
        'post')[:-1] + ' enctype="multipart/form-data">'
    replacements['<mm-post-sender-box>'] = mlist.FormatBox('sender', size=100)
    replacements['<mm-post-subject-box>'] = mlist.FormatBox('subject', size=150)
    replacements['<mm-post-text-box>'] = """
    <textarea rows="12" style="width:100%;" name="text"></textarea>
    """

    replacements['<mm-post-button>'] = mlist.FormatButton(
        'post', text=_('Post'))
    
    replacements['<mm-post-error>'] = message
    
    doc.AddItem(mlist.ParseTags('post.html', replacements, lang))
    print doc.Format()
def main():
    parts = Utils.GetPathPieces()
    if not parts:
        post_overview()
        return

    doc = Document()
    doc.set_language(mm_cfg.DEFAULT_SERVER_LANGUAGE)

    listname = parts[0].lower()
    try:
        mlist = MailList.MailList(listname, lock=0)
    except Errors.MMListError, e:
        # Avoid cross-site scripting attacks
        safelistname = Utils.websafe(listname)
        # Send this with a 404 status.
        print 'Status: 404 Not Found'
        post_overview(_('No such list <em>%(safelistname)s</em>'))
        syslog('error', 'listinfo: No such list "%s": %s', listname, e)
        return

    cgi.maxlen = mlist.max_message_size;
    try:
        cgidata = cgi.FieldStorage()
    except:
        showpost(mlist,mm_cfg.DEFAULT_SERVER_LANGUAGE,
                 'Maximal message length exceeded or parse error!')
        return
    # See if the user want to see this page in other language
    language = cgidata.getvalue('language')
    if not Utils.IsLanguage(language):
        language = mlist.preferred_language
    i18n.set_language(language)
    if not cgidata.getvalue("post"):
        showpost(mlist, language)
        return
    addr = cgidata.getvalue('sender','').strip()
    subj = cgidata.getvalue('subject','').strip()
    body = cgidata.getvalue('text','').strip()
    if not ('.' in addr and '@' in addr ):
        showpost(mlist,language,'Please put your email address into Sender field. "Full Name &lt;name@example.com&gt;" is accepted too, max. 100 chars.')
        return

    msg = MIMEMultipart('mixed')
    try:
        msg['From'] = Header(addr,'ascii')
        msg['Subject'] = Header(subj,'ascii') if subj else '(No subject)'
    except:
        showpost(mlist,language,'Only ASCII chars are supported in sender and subject!')
        return
        
    msg['To'] = mlist.getListAddress('web')
    msgid = unique_message_id(mlist)
    msg['Message-ID'] = msgid;
    msg['Date'] = formatdate(localtime=True)
    if body:
        part = MIMEText(body, 'plain', 'utf-8')
        msg.attach(part)
    attnum = 1
    while attnum < 99:
        try:
            att = cgidata["attachment%02d" % attnum]
        except KeyError:
            break
        if att.filename:
            #Browser should send right mimetypes
            (maintype, subtype) = att.type.split('/')
            opt = att.type_options;
            data = att.file.read()
            if maintype == 'text':
                if 'encoding' not in opt:
                    opt['encoding'] = 'utf-8'
                part = MIMEText(data, subtype, opt['encoding'])
            elif maintype == 'image':
                part = MIMEImage(data, subtype)
            elif maintype == 'audio':
                part = MIMEAudio(data, subtype)
            elif maintype == 'application':
                part = MIMEApplication(data, subtype)
            else:
                part = MIMEApplication(data)
                
            part["Content-Disposition"] = "attachment; filename=" + att.filename
            msg.attach(part)
        attnum+=1;
    Post.inject(listname,msg)
    url = report_submission(msgid, 'Processing...', True)
    print "Status: 303 \nLocation: " + url +"\n"
