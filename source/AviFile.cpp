#include "stdafx.h"

#include "AviFile.h"
#include "snoop.h"
#include "JPEGsnoop.h" // for m_pAppConfig get

#include "WindowBuf.h"

#include "Md5.h"

#include "afxinet.h"

#include "windows.h"
#include "UrlString.h"
#include "DbSigs.h"

#include "General.h"
#include <stack>
#include "sqlite3.h"
#include "tjpgd.h"

#define AVITOOL_VERSION		_T("0.0.20 (bate)")
#define CHEAKCHAR(c)  (((c) >= '0') ? (c) : ' ')
#define UNFCC(fcc)    CHEAKCHAR((char)(fcc)),CHEAKCHAR((char)((fcc) >> 8)),CHEAKCHAR((char)((fcc) >> 16)),CHEAKCHAR((char)((fcc) >> 24))
#define TAG(a,b,c,d)  ((a) | ((b) << 8) | ((c) << 16) | ((unsigned)(d) << 24))

#define SqlSelectIndex(pstrTabName,id,pindexinfo,strErr)    SqlSelectId(SqlSelectIndexCallBack,pstrTabName,id,pindexinfo,strErr)
#define SqlSelectData(pstrTabName,id,pdatainfo,strErr)      SqlSelectId(SqlSelectDataCallBack,pstrTabName,id,pdatainfo,strErr)

static void timecode2cstr(unsigned long timecode,char * buf);
static unsigned long cstr2timecode(const char * cstr);
static int SqlSelectIndexCallBack(void*para , int nCount, char** pValue, char** pName);
static int SqlSelectDataCallBack(void*para , int nCount, char** pValue, char** pName);
static UINT TjpgDecInput(JDEC* jd, BYTE* buff, UINT nbyte);
static double QuantTabQuality(BYTE *qt,BYTE qt_id);

struct datainfo_s {
    unsigned long id;
    unsigned long long offset;
    unsigned long chunksize;
    unsigned long datasize;
    unsigned long errorflag;
    CString errorstr;
	CString qt;
    float quality;
    unsigned long checksum;
    unsigned long indexid;
};

struct indexinfo_s {
    unsigned long id;
    unsigned long long offset;
    unsigned long long dataoffset;
    unsigned long datasize;
    unsigned long flags;
    unsigned long timecode;
    unsigned long dataid;
};

CAviFile::CAviFile(CDocLog* pLog,CimgDecode* pImgDec)
{
    // Ideally this would be passed by constructor, but simply access
    // directly for now.
    CJPEGsnoopApp*  pApp;
    pApp = (CJPEGsnoopApp*)AfxGetApp();
    m_pAppConfig = pApp->m_pAppConfig;
    ASSERT(m_pAppConfig);
    if (DEBUG_EN) m_pAppConfig->DebugLogAdd(_T("CAviFile::CAviFile() Begin"));

    ASSERT(pLog);

    m_pLog = pLog;
    m_pImgDec = pImgDec;

    // Window status bar is not ready yet, wait for call to SetStatusBar()
    m_pStatBar = nullptr;

    // avi file infomation
    m_pFile = nullptr;
    m_strFileName = _T("");
    m_strOutputPath = _T("");
    m_nMoviOfs.clear();
    m_nIdx1Ofs.clear();
    m_bIsOdml = FALSE;
    m_bStreamNum[0] = 
    m_bStreamNum[1] = 0xff;

    m_pAviMainHeader = nullptr;
    m_pAviExtHeader = nullptr;
    m_pAviStreamVideoHeader = nullptr;
    m_pAviStreamAudioHeader = nullptr;
    m_pAviStreamVideoFormat = nullptr;
    m_pAviStreamAudioFormat = nullptr;
    m_pAviVideoSuperIndex   = nullptr;
    m_pAviAudioSuperIndex   = nullptr;
    m_pDB = nullptr;

    m_strVDTabName = _T("VIDEODATA");
    m_strVITabName = _T("VIDEOINDEX");
    m_strADTabName = _T("AUDIODATA");
    m_strAITabName = _T("AUDIOINDEX");

	m_bNeedStop = FALSE;
}

CAviFile::~CAviFile()
{
    Reset();
}

int CAviFile::Reset()
{
    m_strFileName = _T("");
    m_strOutputPath = _T("");
    m_nMoviOfs.clear();
    m_nIdx1Ofs.clear();
    m_bIsOdml = FALSE;
    m_bStreamNum[0] = 
    m_bStreamNum[1] = 0xff;
	m_bNeedStop = FALSE;

    if (m_pFile != nullptr)
    {
        m_pFile->Close();
        delete m_pFile;
        m_pFile = nullptr;
    }

    if(m_pAviMainHeader)
    {
        delete m_pAviMainHeader;
        m_pAviMainHeader = nullptr;
    }
    if(m_pAviExtHeader)
    {
        delete m_pAviExtHeader;
        m_pAviExtHeader = nullptr;
    }
    if(m_pAviStreamVideoHeader)
    {
        delete m_pAviStreamVideoHeader;
        m_pAviStreamVideoHeader = nullptr;
    }
    if(m_pAviStreamAudioHeader)
    {
        delete m_pAviStreamAudioHeader;
        m_pAviStreamAudioHeader = nullptr;
    }
    if(m_pAviStreamVideoFormat)
    {
        delete m_pAviStreamVideoFormat;
        m_pAviStreamVideoFormat = nullptr;
    }
    if(m_pAviStreamAudioFormat)
    {
        delete m_pAviStreamAudioFormat;
        m_pAviStreamAudioFormat = nullptr;
    }
    if(m_pAviVideoSuperIndex )
    {
        delete [] m_pAviVideoSuperIndex;
        m_pAviVideoSuperIndex = nullptr;
    }
    if(m_pAviAudioSuperIndex)
    {
        delete [] m_pAviAudioSuperIndex;
        m_pAviAudioSuperIndex = nullptr;
    }
    if(m_pDB)
    {
        if(sqlite3_close(m_pDB) != SQLITE_OK)
        {

        }
        m_pDB = nullptr;
    }

    return 0;
}

// Asynchronously update a local pointer to the status bar once
// it becomes available. Note that the status bar is not ready by
// the time of the CjfifDecode class constructor call.
//
// INPUT:
// - pStatBar			Ptr to status bar
//
// POST:
// - m_pStatBar
//
void CAviFile::SetStatusBar(CStatusBar* pStatBar)
{
	m_pStatBar = pStatBar;
}

// Update the status bar with a message
void CAviFile::SetStatusText(CString strText)
{
	// Make sure that we have been connected to the status
	// bar of the main window first! Note that it is jpegsnoopDoc
	// that sets this variable.
	if (m_pStatBar) {
#ifndef _DEBUG
		m_pStatBar->SetPaneText(0,strText);
#endif
	}
}

BOOL CAviFile::LoadFile()
{
    BOOL bRes = FALSE;
    LPCTSTR pstrFname = (LPCTSTR)m_pAppConfig->strCurFname;
    try
    {
        m_pFile = new CFile(pstrFname, CFile::modeRead | CFile::typeBinary | CFile::shareDenyNone);
    }
    catch (CFileException* e)
    {
        TCHAR strMsg[MAX_BUF_EX_ERR_MSG];
        CString strError;
        e->GetErrorMessage(strMsg,MAX_BUF_EX_ERR_MSG);
        e->Delete();
        // Note: msg includes m_strPathName
        strError.Format(_T("ERROR: Couldn't open file: [%s]"),strMsg);
        m_pLog->AddLineErr(strError);
        if (m_pAppConfig->bInteractive)
            AfxMessageBox(strError);
        m_pFile = nullptr;

        goto out;
    }

    if(m_pFile->GetLength() < 12)
    {
        m_pLog->AddLineErr(_T("ERROR: File length too small"));
        goto out;
    }
    if(m_pFile->GetLength() > 0xffffffff)
    {
        m_pLog->AddLineErr(_T("ERROR: File length is more than 4GB"));
        goto out;
    }

    m_pFile->SeekToBegin();

    m_strFileName = m_pFile->GetFileTitle();

    int index = m_pFile->GetFilePath().ReverseFind(_T('.'));
    m_strOutputPath = m_pFile->GetFilePath().Left(index) + _T("\\");

	index = m_strFileName.ReverseFind(_T('.'));
	m_strFileTitle = m_strFileName.Left(index);

    bRes = TRUE;
    
out:
    return bRes;
}

// ------------------------------------------------------------ 
// file header check
// ------------------------------------------------------------
int CAviFile::CompletenessCheck()
{
	CString strLog;
	strLog.Format(_T("\nAVI Tool %s by m.jiangyong\n"), AVITOOL_VERSION);
	m_pLog->AddLine(strLog);

    NewDB(0);

	if(!m_bNeedStop)
	{
		HeaderCheck();
	}
	if(!m_bNeedStop)
	{
		IndexScan();
	}
	if(!m_bNeedStop)
	{
		MoviCheck();
	}

	StoreDB2File(m_strFileTitle);

    return 0;
}

int CAviFile::Stop()
{
	m_bNeedStop = TRUE;

	return 0;
}

int CAviFile::HeaderCheck()
{
    unsigned long long ofs,tag_end;
    unsigned long tag,tag1,size;
    unsigned long space;
    unsigned long stream_type = 0;
    unsigned char stream_num  = 0;

    SetStatusText(_T("AVI Header Check ..."));

    std::stack<unsigned long long> tag_ends;
    CString strLog = _T("\n");// for check result
    CString strStu = _T("\n");// for file struct
    
    strLog = _T("*** AVI Header Check Result ***\n");
    m_pLog->AddLineGood(strLog);

    strStu += _T("%AVI Struct Tree :\n");
    strStu += _T("---\n");

    ofs = tell();
    tag = rl32();
    size = rl32();
    tag1 = rl32();

    if((tag != FCC('RIFF')) || (tag1 != FCC('AVI ')))
    {
        strLog.Format(_T("[ERROR] Except 'RIFF AVI ' @0x%08I64x,but find '%c%c%c%c %c%c%c%c'"),ofs,UNFCC(tag),UNFCC(tag1));
        m_pLog->AddLineErr(strLog);
    }

    space = 0;
    AVIStructPrintTag(strStu,space,tag,size,tag1,ofs);
    tag_ends.push(tell() + size - 4);
    tag_end = tag_ends.top();
    
    for(;;)
    {
		if(m_bNeedStop)
		{
			strStu += _T("USER STOP\n");
			strLog = _T("USER STOP\n");
			m_pLog->AddLineGood(strLog);
			break;
		}

        if (eof())
        {
            strStu += _T("EOF\n");
            break;
        }

        ofs = tell();
        tag = rl32();
        size = rl32();

        while(ofs == tag_end)
        {
            if(!tag_ends.empty())
            {
                tag_ends.pop();
            }
            else
            {
                break;
            }

            space -= 4;

            if(!tag_ends.empty())
            {
                tag_end = tag_ends.top();
            }
            else
            {
                break;
            }
        }

        tag_ends.push(tell() + size);
        tag_end = tag_ends.top();
        space += 4;

        switch (tag)
        {
        case FCC('RIFF'):
            tag1 = rl32();
            AVIStructPrintTag(strStu,space,tag,size,tag1,ofs);
            if(tag1 != FCC('AVIX'))
            {
                strLog.Format(_T("[WARN] Except 'AVIX' @0x%08I64x,but find '%c%c%c%c'"),
                              ofs + 8,UNFCC(tag),UNFCC(tag1));
                m_pLog->AddLineWarn(strLog);
            }
            break;
        case FCC('LIST'):
            tag1 = rl32();
            AVIStructPrintTag(strStu,space,tag,size,tag1,ofs);
            switch(tag1)
            {
            case FCC('movi'):
                m_nMoviOfs.push_back(ofs);
                skip(size - 4);
                break;
            case FCC('INFO'):
                space += 4;
                AVIStructReadInfo(strStu,space,size - 4);
                space -= 4;
                break;
            case FCC('ncdt'):
                skip(size - 4);
                break;
            default:
                break;
            }
            
            break;
        case FCC('IDIT'):
        {
            AVIStructPrintTag(strStu,space,tag,size,0,ofs);
            space += 4;
            TCHAR date[64] = { 0 };
            unsigned int i = 0;
            for(;i < min(size,64);i++)
            {
                date[i] = (TCHAR)r8();
            }
            size -= i;

            CString strTmp = CString(_T(' '),space);
            strTmp += date;
            strStu += strTmp + _T('\n');
            skip(size);
            space -= 4;
            break;
        }
        case FCC('dmlh'):
        {
            AVIStructPrintTag(strStu,space,tag,size,0,ofs);

            if(m_pAviExtHeader)
            {
                strLog.Format(_T("[ERROR] Check '%c%c%c%c' again"),UNFCC(tag));
                m_pLog->AddLineErr(strLog);
                delete m_pAviExtHeader;
            }

            unsigned long resize = size;
            space += 4;
            if(size != (sizeof(*m_pAviExtHeader) - 8))
            {
                strLog.Format(_T("[ERROR] '%c%c%c%c' size error,except %d Bytes,but find %d Bytes"),
                              UNFCC(tag),sizeof(*m_pAviExtHeader) - 8,size);
                m_pLog->AddLineErr(strLog);

                resize = min(size,sizeof(*m_pAviExtHeader) - 8);
            }

            m_pAviExtHeader = new AVIEXTHEADER;
            if(m_pAviExtHeader)
            {
                memset(m_pAviExtHeader,0,sizeof(*m_pAviExtHeader));
                m_pAviExtHeader->fcc = tag;
                m_pAviExtHeader->cb  = size;
                if(read((unsigned char *)&m_pAviExtHeader->dwGrandFrames,resize) != resize)
                {
                    if(eof())
                    {
                        strLog.Format(_T("[ERROR] Accidental eof @0x%08I64x"),tell());
                        m_pLog->AddLineErr(strLog);
                    }
                    else
                    {
                        CString strError = _T("ERROR : Read file error");
                        if (m_pAppConfig->bInteractive)
                            AfxMessageBox(strError);
                    }
                    goto out;
                }

                CString strTmp = CString(_T(' '),space);
                CString strTmp1;
                strTmp1.Format(_T("dwGrandFrames : %d\n"),m_pAviExtHeader->dwGrandFrames);
                strStu += strTmp + strTmp1;
                strTmp1 = _T("dwFuture[61]\n");
                strStu += strTmp + strTmp1;
            }
            else
            {
                ASSERT(false);
                goto out;
            }
            skip(size - resize);
            space -= 4;
            break;
        }
        case FCC('amvh'):
            AVIStructPrintTag(strStu,space,tag,size,0,ofs);
            skip(size);
            break;
        case FCC('avih'):
        {
            AVIStructPrintTag(strStu,space,tag,size,0,ofs);
            unsigned long resize = size;
            space += 4;

            if(m_pAviMainHeader)
            {
                strLog.Format(_T("[ERROR] Check '%c%c%c%c' again"),UNFCC(tag));
                m_pLog->AddLineErr(strLog);
                delete m_pAviExtHeader;
            }

            if(size != (sizeof(*m_pAviMainHeader) - 8))
            {
                strLog.Format(_T("[ERROR] '%c%c%c%c' size error,except %d Bytes,but find %d Bytes"),
                              UNFCC(tag),sizeof(*m_pAviExtHeader) - 8,size);
                m_pLog->AddLineErr(strLog);

                resize = min(size,sizeof(*m_pAviMainHeader) - 8);
            }

            m_pAviMainHeader = new AVIMAINHEADER;
            if(m_pAviMainHeader)
            {
                memset(m_pAviMainHeader,0,sizeof(*m_pAviMainHeader));
                m_pAviMainHeader->fcc = tag;
                m_pAviMainHeader->cb  = size;
                if(read((unsigned char *)&m_pAviMainHeader->dwMicroSecPerFrame,resize) != resize)
                {
                    if(eof())
                    {
                        strLog.Format(_T("[ERROR] Accidental eof @0x%08I64x"),tell());
                        m_pLog->AddLineErr(strLog);
                    }
                    else
                    {
                        CString strError = _T("ERROR : Read file error");
                        if (m_pAppConfig->bInteractive)
                            AfxMessageBox(strError);
                    }
                    goto out;
                }

                CString strTmp = CString(_T(' '),space);
                CString strTmp1;
                CString strFlag;

                strFlag += (m_pAviMainHeader->dwFlags & AVIF_HASINDEX) ? _T("AVIF_HASINDEX ") : _T("");
                strFlag += (m_pAviMainHeader->dwFlags & AVIF_MUSTUSEINDEX) ? _T("AVIF_MUSTUSEINDEX ") : _T("");
                strFlag += (m_pAviMainHeader->dwFlags & AVIF_ISINTERLEAVED) ? _T("AVIF_ISINTERLEAVED ") : _T("");
                strFlag += (m_pAviMainHeader->dwFlags & AVIF_TRUSTCKTYPE) ? _T("AVIF_TRUSTCKTYPE ") : _T("");
                strFlag += (m_pAviMainHeader->dwFlags & AVIF_WASCAPTUREFILE) ? _T("AVIF_WASCAPTUREFILE ") : _T("");
                strFlag += (m_pAviMainHeader->dwFlags & AVIF_COPYRIGHTED) ? _T("AVIF_COPYRIGHTED ") : _T("");
                if(m_pAviMainHeader->dwFlags) strFlag = _T(" : ") + strFlag;
                strTmp1.Format(_T("dwMicroSecPerFrame         : %d\n"),m_pAviMainHeader->dwMicroSecPerFrame);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwMaxBytesPerSec           : %d\n"),m_pAviMainHeader->dwMaxBytesPerSec);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwPaddingGranularity       : %d\n"),m_pAviMainHeader->dwPaddingGranularity);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwFlags                    : 0x%08x%s\n"),m_pAviMainHeader->dwFlags,(LPCWSTR)strFlag);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwTotalFrames              : %d\n"),m_pAviMainHeader->dwTotalFrames);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwInitialFrames            : %d\n"),m_pAviMainHeader->dwInitialFrames);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwStreams                  : %d\n"),m_pAviMainHeader->dwStreams);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwSuggestedBufferSize      : 0x%x (%.2fKB)\n"),m_pAviMainHeader->dwSuggestedBufferSize,m_pAviMainHeader->dwSuggestedBufferSize / 1024.0);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwWidth                    : %d\n"),m_pAviMainHeader->dwWidth);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwHeight                   : %d\n"),m_pAviMainHeader->dwHeight);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwReserved[4]\n"));strStu += strTmp + strTmp1;
            }
            else
            {
                ASSERT(false);
                goto out;
            }
            skip(size - resize);
            space -= 4;
            break;
        }
        case FCC('strh'):
        {
            AVIStructPrintTag(strStu,space,tag,size,0,ofs);
            unsigned long resize = size;
            space += 4;

            if(size != (sizeof(AVISTREAMHEADER) - 8))
            {
                strLog.Format(_T("[ERROR] '%c%c%c%c' size error,except %d Bytes,but find %d Bytes"),
                              UNFCC(tag),sizeof(AVISTREAMHEADER) - 8,size);
                m_pLog->AddLineErr(strLog);

                resize = min(size,sizeof(AVISTREAMHEADER) - 8);
            }

            AVISTREAMHEADER * pAviStreamHeader = new AVISTREAMHEADER;
            if(pAviStreamHeader)
            {
                memset(pAviStreamHeader,0,sizeof(*pAviStreamHeader));
                pAviStreamHeader->fcc = tag;
                pAviStreamHeader->cb  = size;
                if(read((unsigned char *)&pAviStreamHeader->fccType,resize) != resize)
                {
                    if(eof())
                    {
                        strLog.Format(_T("[ERROR] Accidental eof @0x%08I64x"),tell());
                        m_pLog->AddLineErr(strLog);
                    }
                    else
                    {
                        CString strError = _T("ERROR : Read file error");
                        if (m_pAppConfig->bInteractive)
                            AfxMessageBox(strError);
                    }
                    goto out;
                }

                CString strTmp = CString(_T(' '),space);
                CString strTmp1;
                CString strFlag;

                strFlag += (pAviStreamHeader->dwFlags & AVISF_DISABLED) ? _T("AVISF_DISABLED ") : _T("");
                strFlag += (pAviStreamHeader->dwFlags & AVISF_VIDEO_PALCHANGES) ? _T("AVISF_VIDEO_PALCHANGES ") : _T("");
                if(pAviStreamHeader->dwFlags) strFlag = _T(" : ") + strFlag;
                strTmp1.Format(_T("fccType                : '%c%c%c%c'\n"),UNFCC(pAviStreamHeader->fccType));strStu += strTmp + strTmp1;
                strTmp1.Format(_T("fccHandler             : 0x%08x '%c%c%c%c'\n"),pAviStreamHeader->fccHandler,UNFCC(pAviStreamHeader->fccHandler));strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwFlags                : 0x%08x%s\n"),pAviStreamHeader->dwFlags, (LPCWSTR)strFlag);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("wPriority              : %d\n"),pAviStreamHeader->wPriority);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("wLanguage              : %d\n"),pAviStreamHeader->wLanguage);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwInitialFrames        : %d\n"),pAviStreamHeader->dwInitialFrames);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwScale                : %d\n"),pAviStreamHeader->dwScale);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwRate                 : %d\n"),pAviStreamHeader->dwRate);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwStart                : %d\n"),pAviStreamHeader->dwStart);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwLength               : %d\n"),pAviStreamHeader->dwLength);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwSuggestedBufferSize  : 0x%x (%.2fKB)\n"),pAviStreamHeader->dwSuggestedBufferSize,pAviStreamHeader->dwSuggestedBufferSize / 1024.0);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwQuality              : %d\n"),pAviStreamHeader->dwQuality);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("dwSampleSize           : %d\n"),pAviStreamHeader->dwSampleSize);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("rcFrame.left           : %d\n"),pAviStreamHeader->rcFrame.left);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("rcFrame.right          : %d\n"),pAviStreamHeader->rcFrame.right);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("rcFrame.top            : %d\n"),pAviStreamHeader->rcFrame.top);strStu += strTmp + strTmp1;
                strTmp1.Format(_T("rcFrame.bottom         : %d\n"),pAviStreamHeader->rcFrame.bottom);strStu += strTmp + strTmp1;

                if(pAviStreamHeader->fccType == FCC('vids'))
                {
                    m_bStreamNum[0] = stream_num++;
                    stream_type = pAviStreamHeader->fccType;
                    if(m_pAviStreamVideoHeader)
                    {
                        strLog.Format(_T("[ERROR] Check 'video stream header' again"));
                        m_pLog->AddLineErr(strLog);
                        delete m_pAviStreamVideoHeader;
                    }

                    m_pAviStreamVideoHeader = new AVISTREAMHEADER;
                    if(!m_pAviStreamVideoHeader)
                    {
                        ASSERT(false);
                        goto out;
                    }

                    memcpy(m_pAviStreamVideoHeader,pAviStreamHeader,sizeof(*pAviStreamHeader));

                    if(!pAviStreamHeader->dwScale)
                        pAviStreamHeader->dwScale = 1;
                    m_nFrameRate = pAviStreamHeader->dwRate / pAviStreamHeader->dwScale;
                    if(!m_nFrameRate)
                        m_nFrameRate = 30;
					else if(m_nFrameRate > 60)
					{
						strLog.Format(_T("[WARN] Queer frame rate : %d"),m_nFrameRate);
						m_pLog->AddLineWarn(strLog);
					}
                }
                else if(pAviStreamHeader->fccType == FCC('auds'))
                {
                    m_bStreamNum[1] = stream_num++;
                    stream_type = pAviStreamHeader->fccType;
                    if(m_pAviStreamAudioHeader)
                    {
                        strLog.Format(_T("[ERROR] Check 'audio stream header' again"));
                        m_pLog->AddLineErr(strLog);
                        delete m_pAviStreamAudioHeader;
                    }

                    m_pAviStreamAudioHeader = new AVISTREAMHEADER;
                    if(!m_pAviStreamAudioHeader)
                    {
                        ASSERT(false);
                        goto out;
                    }

                    memcpy(m_pAviStreamAudioHeader,pAviStreamHeader,sizeof(*pAviStreamHeader));
                }

                if(!(pAviStreamHeader->dwScale && pAviStreamHeader->dwRate))
                {
                    strLog.Format(_T("[WARN] Invalid rate/scaler : %d/%d"),
                                pAviStreamHeader->dwRate,pAviStreamHeader->dwScale);
                    m_pLog->AddLineWarn(strLog);
                }

                delete pAviStreamHeader;
            }
            else
            {
                ASSERT(false);
                goto out;
            }
            skip(size - resize);
            space -= 4;
            break;
        }
        case FCC('strf'):
        {
            AVIStructPrintTag(strStu,space,tag,size,0,ofs);
            unsigned long resize = size;
            space += 4;

            if(stream_type == FCC('vids'))
            {
                if(size != (sizeof(BITMAPINFOHEADER)))
                {
                    unsigned long bisize = rl32();
                    if(size != bisize)
                    {
                        strLog.Format(_T("[ERROR] video '%c%c%c%c' size error,except %d Bytes,but find %d Bytes"),
                                      UNFCC(tag),sizeof(BITMAPINFOHEADER),size);
                        m_pLog->AddLineErr(strLog);
                    }
                    skip(-4);

                    resize = min(size,sizeof(BITMAPINFOHEADER));
                }

                if(m_pAviStreamVideoFormat)
                {
                    strLog.Format(_T("[ERROR] Check 'video stream format' again"));
                    m_pLog->AddLineErr(strLog);
                    delete m_pAviStreamVideoFormat;
                }

                m_pAviStreamVideoFormat = new BITMAPINFOHEADER;
                if(m_pAviStreamVideoFormat)
                {
                    memset(m_pAviStreamVideoFormat,0,sizeof(*m_pAviStreamVideoFormat));
                    if(read((unsigned char *)m_pAviStreamVideoFormat,resize) != resize)
                    {
                        if(eof())
                        {
                            strLog.Format(_T("[ERROR] Accidental eof @0x%08I64x"),tell());
                            m_pLog->AddLineErr(strLog);
                        }
                        else
                        {
                            CString strError = _T("ERROR : Read file error");
                            if (m_pAppConfig->bInteractive)
                                AfxMessageBox(strError);
                        }
                        goto out;
                    }

                    CString strTmp = CString(_T(' '),space);
                    CString strTmp1;
                    strTmp1.Format(_T("biSize                 : %d\n"),m_pAviStreamVideoFormat->biSize);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("biWidth                : %d\n"),m_pAviStreamVideoFormat->biWidth);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("biHeight               : %d\n"),m_pAviStreamVideoFormat->biHeight);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("biPlanes               : %d\n"),m_pAviStreamVideoFormat->biPlanes);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("biBitCount             : %d\n"),m_pAviStreamVideoFormat->biBitCount);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("biCompression          : '%c%c%c%c'\n"),UNFCC(m_pAviStreamVideoFormat->biCompression));strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("biSizeImage            : %d (%.2fKB)\n"),m_pAviStreamVideoFormat->biSizeImage,m_pAviStreamVideoFormat->biSizeImage / 1024.0);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("biXPelsPerMeter        : %d\n"),m_pAviStreamVideoFormat->biXPelsPerMeter);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("biYPelsPerMeter        : %d\n"),m_pAviStreamVideoFormat->biYPelsPerMeter);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("biClrUsed              : %d\n"),m_pAviStreamVideoFormat->biClrUsed);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("biClrImportant         : %d\n"),m_pAviStreamVideoFormat->biClrImportant);strStu += strTmp + strTmp1;
                }
                else
                {
                    ASSERT(false);
                    goto out;
                }
            }
            else if(stream_type == FCC('auds'))
            {
                if(size < (sizeof(WAVEFORMATEX)))
                {
                    strLog.Format(_T("[WARN] audio '%c%c%c%c' size error,except >= %d Bytes,but find %d Bytes"),
                                    UNFCC(tag),sizeof(WAVEFORMATEX),size);
                    m_pLog->AddLineWarn(strLog);
                }

                resize = min(size,sizeof(WAVEFORMATEX));

                if(m_pAviStreamAudioFormat)
                {
                    strLog.Format(_T("[ERROR] Check 'audio stream format' again"));
                    m_pLog->AddLineErr(strLog);
                    delete m_pAviStreamAudioFormat;
                }

                m_pAviStreamAudioFormat = new WAVEFORMATEX;
                if(m_pAviStreamAudioFormat)
                {
                    memset(m_pAviStreamAudioFormat,0,sizeof(*m_pAviStreamAudioFormat));
                    if(read((unsigned char *)m_pAviStreamAudioFormat,resize) != resize)
                    {
                        if(eof())
                        {
                            strLog.Format(_T("[ERROR] Accidental eof @0x%08I64x"),tell());
                            m_pLog->AddLineErr(strLog);
                        }
                        else
                        {
                            CString strError = _T("ERROR : Read file error");
                            if (m_pAppConfig->bInteractive)
                                AfxMessageBox(strError);
                        }
                        goto out;
                    }

                    CString strTmp = CString(_T(' '),space);
                    CString strTmp1;
                    strTmp1.Format(_T("wFormatTag             : 0x%04x\n"),m_pAviStreamAudioFormat->wFormatTag);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("nChannels              : %d\n"),m_pAviStreamAudioFormat->nChannels);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("nSamplesPerSec         : %d\n"),m_pAviStreamAudioFormat->nSamplesPerSec);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("nAvgBytesPerSec        : %d\n"),m_pAviStreamAudioFormat->nAvgBytesPerSec);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("nBlockAlign            : %d\n"),m_pAviStreamAudioFormat->nBlockAlign);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("wBitsPerSample         : %d\n"),m_pAviStreamAudioFormat->wBitsPerSample);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("cbSize                 : %d\n"),m_pAviStreamAudioFormat->cbSize);strStu += strTmp + strTmp1;
                }
                else
                {
                    ASSERT(false);
                    goto out;
                }
            }
            skip(size - resize);
            space -= 4;
            break;
        }
        case FCC('indx'):
        {
            AVIStructPrintTag(strStu,space,tag,size,0,ofs);

            if((size < (sizeof(AVIMETAINDEX) - 8)) || (size >= 0xffffffff))
            {
                strLog.Format(_T("[ERROR] '%c%c%c%c'(@0x%08I64x) size error,except >= %d Bytes,but find %d Bytes"),
                                UNFCC(tag),ofs,sizeof(AVIMETAINDEX),size);
                m_pLog->AddLineErr(strLog);
                skip(size);
                break;
            }

            AVIMETAINDEX *pavimetaindex = (AVIMETAINDEX *)(new BYTE[32]);
            if(!pavimetaindex)
            {
                ASSERT(false);
                goto out;
            }
            space += 4;
            pavimetaindex->fcc = tag;
            pavimetaindex->cb = size;
            pavimetaindex->wLongsPerEntry = (WORD)rl16();
            pavimetaindex->bIndexSubType = (BYTE)r8();
            pavimetaindex->bIndexType = (BYTE)r8();
            pavimetaindex->nEntriesInUse = rl32();
            pavimetaindex->dwChunkId = rl32();
            pavimetaindex->dwReserved[0] = rl32();
            pavimetaindex->dwReserved[1] = rl32();
            pavimetaindex->dwReserved[2] = rl32();

            if(Valid_SUPERINDEX(pavimetaindex))
            {
                AVISUPERINDEX *pavisuperindex = (AVISUPERINDEX *)(new BYTE[size + 8]);
                if(pavisuperindex)
                {
                    seek(ofs);
                    if(read((unsigned char *)pavisuperindex,size + 8) != (size + 8))
                    {
                        if(eof())
                        {
                            strLog.Format(_T("[ERROR] Accidental eof @0x%08I64x"),tell());
                            m_pLog->AddLineErr(strLog);
                        }
                        else
                        {
                            CString strError = _T("ERROR : Read file error");
                            if (m_pAppConfig->bInteractive)
                                AfxMessageBox(strError);
                        }
                        goto out;
                    }
					pavisuperindex->fcc = ofs;
                    if(pavimetaindex->dwChunkId == TAG('0','0'+m_bStreamNum[0],'d','c'))
                    {
                        if(m_pAviVideoSuperIndex)
                        {
                            strLog.Format(_T("[ERROR] Check 'video super index' again"));
                            m_pLog->AddLineErr(strLog);
                            delete [] m_pAviVideoSuperIndex;
                        }
                        m_pAviVideoSuperIndex = pavisuperindex;
                    }
                    else if(pavimetaindex->dwChunkId == TAG('0','0'+m_bStreamNum[1],'w','b'))
                    {
                        if(m_pAviAudioSuperIndex)
                        {
                            strLog.Format(_T("[ERROR] Check 'audio super index' again"));
                            m_pLog->AddLineErr(strLog);
                            delete [] m_pAviAudioSuperIndex;
                        }
                        m_pAviAudioSuperIndex = pavisuperindex;
                    }
                }
                else
                {
                    ASSERT(false);
                    goto out;
                }
            }

            CString strTmp = CString(_T(' '),space);
            CString strTmp1;
            strTmp1.Format(_T("wLongsPerEntry         : %d\n"),pavimetaindex->wLongsPerEntry);strStu += strTmp + strTmp1;
            strTmp1.Format(_T("bIndexSubType          : %d\n"),pavimetaindex->bIndexSubType);strStu += strTmp + strTmp1;
            strTmp1.Format(_T("bIndexType             : %d\n"),pavimetaindex->bIndexType);strStu += strTmp + strTmp1;
            strTmp1.Format(_T("nEntriesInUse          : %d\n"),pavimetaindex->nEntriesInUse);strStu += strTmp + strTmp1;
            strTmp1.Format(_T("dwChunkId              : '%c%c%c%c'\n"),UNFCC(pavimetaindex->dwChunkId));strStu += strTmp + strTmp1;
            strTmp1.Format(_T("dwReserved[0]          : 0x%08x\n"),pavimetaindex->dwReserved[0]);strStu += strTmp + strTmp1;
            strTmp1.Format(_T("dwReserved[1]          : 0x%08x\n"),pavimetaindex->dwReserved[1]);strStu += strTmp + strTmp1;
            strTmp1.Format(_T("dwReserved[2]          : 0x%08x\n"),pavimetaindex->dwReserved[2]);strStu += strTmp + strTmp1;

            delete pavimetaindex;
            m_bIsOdml = TRUE;
            space -= 4;
            break;
        }
        case FCC('idx1'):
             AVIStructPrintTag(strStu,space,tag,size,0,ofs);
             m_nIdx1Ofs.push_back(ofs);
             skip(size);
             break;
        case FCC('vprp'):
            {
                typedef struct {
                   DWORD   CompressedBMHeight;
                   DWORD   CompressedBMWidth;
                   DWORD   ValidBMHeight;
                   DWORD   ValidBMWidth;
                   DWORD   ValidBMXOffset;
                   DWORD   ValidBMYOffset;
                   DWORD   VideoXOffsetInT;
                   DWORD   VideoYValidStartLine;
                } VIDEO_FIELD_DESC;

                typedef struct {
                   DWORD   VideoFormatToken;
                   DWORD   VideoStandard;
                   DWORD   dwVerticalRefreshRate;
                   DWORD   dwHTotalInT;
                   DWORD   dwVTotalInLines;
                   DWORD   dwFrameAspectRatio;
                   DWORD   dwFrameWidthInPixels;
                   DWORD   dwFrameHeightInLines;
                   DWORD   nbFieldPerFrame;
                   //VIDEO_FIELD_DESC   FieldInfo[nbFieldPerFrame];
                } VIDEOPROPHEADER;

                AVIStructPrintTag(strStu,space,tag,size,0,ofs);
                unsigned long resize = size;
                space += 4;
                if((size < (sizeof(VIDEOPROPHEADER) + sizeof(VIDEO_FIELD_DESC))) || (size >= 0xffffffff))
                {
                    strLog.Format(_T("[ERROR] '%c%c%c%c'(@0x%08x) size error,except >= %d Bytes,but find %d Bytes"),
                                    UNFCC(tag),ofs,sizeof(VIDEOPROPHEADER) + sizeof(VIDEO_FIELD_DESC),size);
                    m_pLog->AddLineErr(strLog);
                }

                VIDEOPROPHEADER VideoPropHeader;
                memset(&VideoPropHeader,0,sizeof(VIDEOPROPHEADER));
                resize = min(size,sizeof(VIDEOPROPHEADER));
                if(read((unsigned char *)&VideoPropHeader,resize) != resize)
                {
                    if(eof())
                    {
                        strLog.Format(_T("[ERROR] Accidental eof @0x%08I64x"),tell());
                        m_pLog->AddLineErr(strLog);
                    }
                    else
                    {
                        CString strError = _T("ERROR : Read file error");
                        if (m_pAppConfig->bInteractive)
                            AfxMessageBox(strError);
                    }
                    goto out;
                }
                else
                {
                    VIDEO_FIELD_DESC * p_video_field_desc = nullptr;

                    CString strTmp = CString(_T(' '),space);
                    CString strTmp1;
                    strTmp1.Format(_T("VideoFormatToken       : %d\n"),VideoPropHeader.VideoFormatToken);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("VideoStandard          : %d\n"),VideoPropHeader.VideoStandard);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("dwVerticalRefreshRate  : %d\n"),VideoPropHeader.dwVerticalRefreshRate);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("dwHTotalInT            : %d\n"),VideoPropHeader.dwHTotalInT);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("dwVTotalInLines        : %d\n"),VideoPropHeader.dwVTotalInLines);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("dwFrameAspectRatio     : %d\n"),VideoPropHeader.dwFrameAspectRatio);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("dwFrameWidthInPixels   : %d\n"),VideoPropHeader.dwFrameWidthInPixels);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("dwFrameHeightInLines   : %d\n"),VideoPropHeader.dwFrameHeightInLines);strStu += strTmp + strTmp1;
                    strTmp1.Format(_T("nbFieldPerFrame        : %d\n"),VideoPropHeader.nbFieldPerFrame);strStu += strTmp + strTmp1;

                    if(VideoPropHeader.nbFieldPerFrame)
                    {
                        p_video_field_desc = (VIDEO_FIELD_DESC *)new BYTE[sizeof(VIDEO_FIELD_DESC) * VideoPropHeader.nbFieldPerFrame];
                        if(!p_video_field_desc)
                        {
                            ASSERT(false);
                            goto out;
                        }
                        
                        unsigned int resize1 = min(size - resize ,sizeof(VIDEOPROPHEADER) * VideoPropHeader.nbFieldPerFrame);
                        if(read((unsigned char *)p_video_field_desc,resize1) != resize1)
                        {
                            if(eof())
                            {
                                strLog.Format(_T("[ERROR] Accidental eof @0x%08I64x"),tell());
                                m_pLog->AddLineErr(strLog);
                            }
                            else
                            {
                                CString strError = _T("ERROR : Read file error");
                                if (m_pAppConfig->bInteractive)
                                    AfxMessageBox(strError);
                            }
                            goto out;
                        }
                        else
                        {
                            for(int i = 0;i < (int)VideoPropHeader.nbFieldPerFrame;i++)
                            {
                                strTmp1.Format(_T("FieldInfo[%d] : \n"),i);strStu += strTmp + strTmp1;
                                strTmp1.Format(_T( "CompressedBMHeight     : %d\n"),p_video_field_desc->CompressedBMHeight);strStu += strTmp + strTmp1;
                                strTmp1.Format(_T( "CompressedBMWidth      : %d\n"),p_video_field_desc->CompressedBMWidth);strStu += strTmp + strTmp1;
                                strTmp1.Format(_T( "ValidBMHeight          : %d\n"),p_video_field_desc->ValidBMHeight);strStu += strTmp + strTmp1;
                                strTmp1.Format(_T( "ValidBMWidth           : %d\n"),p_video_field_desc->ValidBMWidth);strStu += strTmp + strTmp1;
                                strTmp1.Format(_T( "ValidBMXOffset         : %d\n"),p_video_field_desc->ValidBMXOffset);strStu += strTmp + strTmp1;
                                strTmp1.Format(_T( "ValidBMYOffset         : %d\n"),p_video_field_desc->ValidBMYOffset);strStu += strTmp + strTmp1;
                                strTmp1.Format(_T( "VideoXOffsetInT        : %d\n"),p_video_field_desc->VideoXOffsetInT);strStu += strTmp + strTmp1;
                                strTmp1.Format(_T( "VideoYValidStartLine   : %d\n"),p_video_field_desc->VideoYValidStartLine);strStu += strTmp + strTmp1;
                            }
                        }

                        resize += resize1;
                        delete [] p_video_field_desc;
                    }
                }
                space -= 4;
                skip(size - resize);
                break;
            }

        case FCC('strn'):
             AVIStructPrintTag(strStu,space,tag,size,0,ofs);
             skip(size);
             break;
        case FCC('strd'):
            AVIStructPrintTag(strStu,space,tag,size,0,ofs);
            if(!size)
            {
                strLog.Format(_T("[WARN] '%c%c%c%c' size is %d"),UNFCC(tag),size);
                m_pLog->AddLineWarn(strLog);
            }
            skip(size);
            break;
        case FCC('JUNK'):
            AVIStructPrintTag(strStu,space,tag,size,0,ofs);
            skip(size);
            break;
        default:
            {
                if(!tag && !size)
                {
                    int cnt = 2;
                    while (!rl32())
                    {
                        if(eof())
                            break;
                        cnt++;
                    }

                    if(!eof())
                        skip(-4);

                    strLog.Format(_T("[WARN] %d zero word @0x%08I64x"),cnt,ofs);
                    m_pLog->AddLineWarn(strLog);

                    tag_end = tell();
                }
                else
                {
                    //TODO:对非法数据的处理
                    if(size > 1024*1024)
                    {
                        CString strTmp = CString();strTmp.Format(_T("ABORT @0x%08x,0x%08I64x Byte"),ofs,size);
                        strStu += CString(_T(' '),space) + strTmp;

                        strLog.Format(_T("[ERROR] unkonw chunk @0x%08I64x,and size is %dByte"),ofs,size);
                        m_pLog->AddLineErr(strLog);
                        goto out;
                    }
                    AVIStructPrintTag(strStu,space,tag,size,0,ofs);
                    skip(size);
                }
                break;
            }
        }
    }

out:
    
    m_pLog->AddLine(strStu);
    SetStatusText(_T("AVI Header Check Done"));
    return 0;
}

void CAviFile::AVIStructPrintTag(CString &strDest,int nPreSpace,unsigned long nTag,unsigned long nSize,
                        unsigned long nTag1,unsigned long long nPos)
{   
    int i;
    const int line_len = 50;
    CString tmpStr = _T("");
    CString strPre = CString(_T(' '),nPreSpace);
    
    tmpStr.Format(_T("%c%c%c%c "),UNFCC(nTag)); strPre += tmpStr;
    tmpStr.Format(_T("0x%08x "),nSize);strPre += tmpStr;
    if(nTag1 != 0)
    {
        tmpStr.Format(_T("%c%c%c%c "),UNFCC(nTag1)); strPre += tmpStr;
    }

    i = line_len - strPre.GetLength();
    while (i > 0)
    {
        strPre += _T('.');
        i--;
    }

    tmpStr.Format(_T("[@0x%08I64x, "),nPos); strPre += tmpStr;
    if(nSize > (1024*1024*1024 - 1))
    {
        tmpStr.Format(_T("%.2fGB"),nSize/(1024*1024*1024.0));
    }
    else if(nSize > (1024*1024 - 1))
    {
        tmpStr.Format(_T("%.2fMB"),nSize/(1024*1024.0));
    }
    else if(nSize > (1024 - 1))
    {
        tmpStr.Format(_T("%.2fKB"),nSize/(1024.0));
    }
    else
    {
        tmpStr.Format(_T("%dB"),nSize);
    }
    strPre += tmpStr + _T("]\n");
    strDest += strPre;
}

void CAviFile::AVIStructReadInfo(CString &strDest,int nPreSpace,unsigned long nSize)
{
	while (nSize > 8)
	{
		unsigned long i;
		TCHAR c;
		CString strPre = CString(_T(' '), nPreSpace);

		if (tell() & 1) {
			r8(); nSize -= 1;
		}

		unsigned long code = rl32(); nSize -= 4;
		unsigned long size = rl32(); nSize -= 4;
		size = min(size, nSize);

		c = (TCHAR)((code >> 0) & 0xFF); strPre += (c == 0) ? _T('?'): c;
		c = (TCHAR)((code >> 8) & 0xFF); strPre += (c == 0) ? _T('?') : c;
		c = (TCHAR)((code >> 16) & 0xFF); strPre += (c == 0) ? _T('?') : c;
		c = (TCHAR)((code >> 24) & 0xFF); strPre += (c == 0) ? _T('?') : c;
		strPre += _T(" : ");

		for (i = 0; i < size; i++)
		{
			c = (TCHAR)r8();
			if (c == 0)
			{
				skip(size - 1 - i);
				break;
			}
			strPre += c;
		}

		strPre += _T('\n');
		strDest += strPre;
		nSize -= size;
	}

	skip(nSize);
}

int CAviFile::AVIFindNextTag(unsigned long long *ofs,unsigned long *tag)
{
    int res = 0;
    unsigned long long OFS = tell();

    unsigned long long _ofs;
    unsigned long _tag;

    const unsigned long vtag0 = TAG('0','0'+m_bStreamNum[0],'d','c');
    const unsigned long vtag1 = TAG('0','0'+m_bStreamNum[0],'i','x');
    const unsigned long vtag2 = TAG('i','x','0','0'+m_bStreamNum[0]);
    const unsigned long atag0 = TAG('0','0'+m_bStreamNum[1],'w','b');
    const unsigned long atag1 = TAG('0','0'+m_bStreamNum[1],'i','x');
    const unsigned long atag2 = TAG('i','x','0','0'+m_bStreamNum[1]);

    while(1)
    {
        _ofs = tell();
        _tag = rl32();

        if(eof())
        {
            if(ofs) *ofs = _ofs;
            res = -1;
            break;
        }

        if((_tag == vtag0) || 
           (_tag == vtag1) || 
           (_tag == vtag2) || 
           (_tag == atag0) ||
           (_tag == atag1) ||
           (_tag == atag2) ||
           (_tag == FCC('LIST')) ||
           (_tag == FCC('idx1')) ||
           (_tag == FCC('JUNK')) ||
           (_tag == FCC('RIFF')) ||
           (_tag == FCC('INFO')))
        {
            if(ofs) *ofs = _ofs;
            if(tag) *tag = _tag;
            break;
        }
    }

    seek(OFS);
    return res;
}

// ------------------------------------------------------------ 
// file index check
// ------------------------------------------------------------
int CAviFile::OldIndexScan(unsigned long long index_start,unsigned long timecode_start,unsigned long *timecode_end)
{
    unsigned long long ofs,end,movi_start;
    unsigned long tag,size,IDXSIZE,flags,pos;
    const unsigned long vtag0 = TAG('0','0'+m_bStreamNum[0],'d','c');
    const unsigned long atag0 = TAG('0','0'+m_bStreamNum[1],'w','b');
    unsigned long time = timecode_start >> 16;
    unsigned long frame = timecode_start & 0xffff;
    unsigned long frame_rate = m_nFrameRate;
    struct indexinfo_s indexinfo;
    CString strLog;

    movi_start = m_nMoviOfs[0] + 8;
    seek(index_start);
    tag = rl32();
    IDXSIZE = rl32();
    end = tell() + IDXSIZE;

    while (true)
    {
        ofs = tell();
        if(ofs >= end) break;
        if((ofs + 16) > end) break;
        if(eof()) break;
        
        tag   = rl32();
        flags = rl32();
        pos   = rl32();
        size  = rl32();

        indexinfo.id = 0;
        indexinfo.offset = ofs;
        indexinfo.dataoffset = pos + movi_start;
        indexinfo.datasize = size;
        indexinfo.flags = flags;
        indexinfo.timecode = 0;
        indexinfo.dataid = 0;

		strLog.Format(_T("AVI old index scan (%.2f%%)"),(ofs + IDXSIZE - end) * 100.0 / IDXSIZE);
		SetStatusText(strLog);

        if(tag == vtag0)
        {
            if(pos)
            {
                indexinfo.timecode = (time << 16) | (frame & 0xffff);
                frame++;
                if(frame >= frame_rate)
                {
                    time++;
                    frame = 0;
                }

                if(SqlInsertIndex(m_strVITabName,&indexinfo,strLog))
                {
                    //TODO:错误处理
					if (m_pAppConfig->bInteractive)
						AfxMessageBox(strLog);
                }
            }
            else
            {
                strLog.Format(_T("[ERROR] Error index : offset is 0,@0x%08I64x"),ofs);
                m_pLog->AddLineErr(strLog);
            }

            if(!size)
            {
                strLog.Format(_T("[WARN] Error index : size is 0,@0x%08I64x"),ofs);
                m_pLog->AddLineWarn(strLog);
            }
        }
        else if(tag == atag0)
        {
            if(pos)
            {
                if(SqlInsertIndex(m_strAITabName,&indexinfo,strLog))
                {
                    //TODO:错误处理
					if (m_pAppConfig->bInteractive)
						AfxMessageBox(strLog);
                }
            }
            else
            {
                strLog.Format(_T("[ERROR] Error index : offset is 0,@0x%08I64x"),ofs);
                m_pLog->AddLineErr(strLog);
            }

            if(!size)
            {
                strLog.Format(_T("[WARN] Error index : size is 0,@0x%08I64x"),ofs);
                m_pLog->AddLineWarn(strLog);
            }
        }
        else if((tag == FCC('LIST')) || (tag == FCC('JUNK')))
        {
            skip((long)flags - 8);
        }
        else
        {
            strLog.Format(_T("[WARN] Unkown tag:0x%08x,size:0x%08x,@0x%08I64x"),tag,flags,ofs - 8);
            m_pLog->AddLineWarn(strLog);
            skip(-8);

            unsigned long long next_ofs;
            if(AVIFindNextTag(&next_ofs,nullptr))
            {
                strLog.Format(_T("[WARN] Could not find any index,abort"),tag,flags);
                m_pLog->AddLineWarn(strLog);
                break;
            }
            else
            {
                seek(next_ofs);
            }
        }
    }

    if(timecode_end)
        *timecode_end = (time << 16) | (frame & 0xffff);

    return 0;
}

int CAviFile::OdmlStdIndexScan(unsigned long long stdindx_start,unsigned long duration,unsigned long streamid,
                               unsigned long timecode_start,unsigned long *timecode_end)
{
    int res = -1;
    unsigned long tag1,tag2;
    unsigned long long ofs;
    unsigned long time = timecode_start >> 16;
    unsigned long frame = timecode_start & 0xffff;
    unsigned long frame_rate = m_nFrameRate;
    AVISTDINDEX * p_avistdindex = nullptr;
    CString strLog,strTabName;
    struct indexinfo_s indexinfo;
    BYTE buf[32];

    seek(stdindx_start);
    if(read(buf,sizeof(buf)) != sizeof(buf))
    {
        if(eof())
        {
            strLog.Format(_T("[ERROR] Accidental eof @0x%08I64x"),tell());
            m_pLog->AddLineErr(strLog);
        }
        else
        {
            CString strError = _T("ERROR : Read file error");
            if (m_pAppConfig->bInteractive)
                AfxMessageBox(strError);
        }
        goto out;
    }
    else
    {
        p_avistdindex = (AVISTDINDEX *)buf;
        tag1 = TAG('0','0'+m_bStreamNum[streamid],'i','x');
        tag2 = TAG('i','x','0','0'+m_bStreamNum[streamid]);
        
        if((p_avistdindex->fcc != FCC('indx') && 
            p_avistdindex->fcc != tag1 &&
            p_avistdindex->fcc != tag2) ||
           (p_avistdindex->cb < 22 + p_avistdindex->nEntriesInUse * sizeof(AVISTDINDEX_ENTRY)) ||
           (p_avistdindex->wLongsPerEntry != 2) ||
           (p_avistdindex->bIndexSubType != 0) ||
           (p_avistdindex->bIndexType != AVI_INDEX_OF_CHUNKS)
           )
        {
            strLog.Format(_T("[ERROR] Except standard index(stream : %d) @0x%08I64x,but find tag:0x%08x,size:0x%08x"),streamid,stdindx_start,p_avistdindex->fcc,p_avistdindex->cb);
            m_pLog->AddLineErr(strLog);
            goto out;
        }

        if(streamid == 0) 
        {
            tag1 = TAG('0','0'+m_bStreamNum[streamid],'d','c');
            strTabName = m_strVITabName;
        }
        else if(streamid == 1)
        {
            tag1 = TAG('0','0'+m_bStreamNum[streamid],'w','b');
            strTabName = m_strAITabName;
        }

        if(p_avistdindex->dwChunkId != tag1)
        {
            strLog.Format(_T("[ERROR] Except standard index of '%c%c%c%c' @0x%08I64x,but find tag:'%c%c%c%c'"),UNFCC(tag1),stdindx_start,UNFCC(p_avistdindex->dwChunkId));
            m_pLog->AddLineErr(strLog);
            goto out;
        }

        if(p_avistdindex->qwBaseOffset > stdindx_start)
        {
            strLog.Format(_T("[ERROR] Except standard index @0x%08I64x,but find tag:0x%08x,size:0x%08x"),stdindx_start,p_avistdindex->fcc,p_avistdindex->cb);
            m_pLog->AddLineErr(strLog);
            goto out;
        }

		if((streamid == 0) && duration && (duration != p_avistdindex->nEntriesInUse))
		{
            strLog.Format(_T("[WARN] Except nEntriesInUse of standard index @0x%08I64x is %d,but find %d"),stdindx_start,duration,p_avistdindex->nEntriesInUse);
            m_pLog->AddLineErr(strLog);
		}

        for(unsigned long i = 0;i < p_avistdindex->nEntriesInUse;i++)
        {
            ofs  = tell();

            if(eof())
            {
                strLog.Format(_T("[ERROR] Find EOF @0x%08I64x"),ofs);
                m_pLog->AddLineErr(strLog);
                goto out;
            }

			strLog.Format(_T("AVI odml index scan (%.2f%%)"),i * 100.0 / p_avistdindex->nEntriesInUse);
			SetStatusText(strLog);
            
            tag1 = rl32();
            tag2 = rl32();

            indexinfo.id = 0;
            indexinfo.offset = ofs;
            indexinfo.dataoffset = p_avistdindex->qwBaseOffset + tag1 - 8;//point to '00dc'
            indexinfo.datasize = tag2 & AVISTDINDEX_SIZEMASK;
            indexinfo.flags = (tag2 & AVISTDINDEX_DELTAFRAME) ? 0 : AVIIF_KEYFRAME;
            indexinfo.timecode = 0;
            indexinfo.dataid = 0;

            if(streamid == 0)
            {
                indexinfo.timecode = (time << 16) | (frame & 0xffff);
                frame++;
                if(frame >= frame_rate)
                {
                    time++;
                    frame = 0;
                }
            }

            if(SqlInsertIndex(strTabName,&indexinfo,strLog))
            {
                //TODO:错误处理
				if (m_pAppConfig->bInteractive)
					AfxMessageBox(strLog);
            }

			if(m_bNeedStop)
			{
				break;
			}
        }

        res = 0;
    }

out:
    if(timecode_end)
        *timecode_end = (time << 16) | (frame & 0xffff);
    return res;
}

int CAviFile::OdmlIndexScan()
{
	DWORDLONG qwOffset,qwOffset0 = 0xffffffff;
	DWORD    dwSize;
	DWORD    dwDuration;
	int      LEN;

	CString strLog,strTmp;
	unsigned long timecode = 0,nstream,i;

	for(nstream = 0;nstream < 2;nstream++)
	{
		if(m_bNeedStop)
		{
			break;
		}

		AVISUPERINDEX * pavisuperindex;
		if(nstream == 0)
			pavisuperindex = m_pAviVideoSuperIndex;
		else
		{
			pavisuperindex = m_pAviAudioSuperIndex;
		}

		if(pavisuperindex)
		{
			for(i = 0;i < pavisuperindex->nEntriesInUse;i++)
			{
				if(m_bNeedStop)
				{
					break;
				}

				strLog.Format(_T("[ERROR] Super index('%c%c%c%c') error (@0x%08I64x): "),UNFCC(pavisuperindex->dwChunkId),pavisuperindex->fcc + (DWORD)&pavisuperindex->aIndex[i] - (DWORD)pavisuperindex);
				LEN = strLog.GetLength();

				qwOffset = pavisuperindex->aIndex[i].qwOffset;
				dwSize = pavisuperindex->aIndex[i].dwSize;
				dwDuration = pavisuperindex->aIndex[i].dwDuration;

				if(qwOffset0 == qwOffset)
				{
					strTmp= _T("qwOffset is same with last stdindex,");
					strLog += strTmp;
				}

				qwOffset0 = qwOffset;

				if((qwOffset > m_pFile->GetLength()) || !qwOffset)
				{
					strTmp.Format(_T("qwOffset is %d,"),qwOffset);
					strLog += strTmp;
				}
				if((dwSize > m_pFile->GetLength()) || !dwSize)
				{
					strTmp.Format(_T("dwSize is %d,"),dwSize);
					strLog += strTmp;
				}

				if(strLog.GetLength() != LEN)
				{
					m_pLog->AddLineErr(strLog);
					continue;
				}

				if(!dwDuration)
				{
					strTmp.Format(_T("dwDuration is %d"),dwDuration);
					strLog += strTmp;
					m_pLog->AddLineErr(strLog);
				}

				OdmlStdIndexScan(qwOffset,dwDuration,nstream,(nstream == 0) ? timecode : 0,(nstream == 0) ? &timecode : nullptr);

				if(eof())
				{
					break;
				}
			}
		}
	}

    return 0;
}

int CAviFile::IndexScan()
{
    CString strLog;// for check result
    unsigned long timecode = 0;
    strLog = _T("\n*** AVI INDEX Check Result ***");
    m_pLog->AddLineGood(strLog);

	SetStatusText(_T("AVI index scanf ..."));

    if(m_bIsOdml)
    {
        OdmlIndexScan();
    }
    else
    {
        if(m_nIdx1Ofs.empty())
        {

        }
        else
        {
            for(unsigned int i = 0;i < m_nIdx1Ofs.size();i++)
            {
                OldIndexScan(m_nIdx1Ofs[i],timecode,&timecode);
            }
            
        }
    }

	if(m_bNeedStop)
	{
		strLog = _T("USER STOP\n");
		m_pLog->AddLineGood(strLog);
	}

	SetStatusText(_T("Done"));
    return 0;
}

// ------------------------------------------------------------ 
// file data check
// ------------------------------------------------------------
int CAviFile::DataCheckSum(CString &strOut,unsigned long long start,unsigned long long len)
{
	len = len;
	start = start;
	strOut = strOut;
	return 0;
}

int CAviFile::VideoDataCheck(struct datainfo_s * p_datainfo,unsigned long chunk_size,unsigned long *used)
{
	USES_CONVERSION;
    unsigned long long ofs = tell();
	BYTE *qt = nullptr,qt_id,i;
	CString strQt;
	JDEC* jd = nullptr;
	JRESULT jres = JDR_OK;

	p_datainfo->id        = 0;
	p_datainfo->offset    = ofs;
	p_datainfo->chunksize = chunk_size;
	p_datainfo->datasize  = 0;
	p_datainfo->errorflag = 0;
	p_datainfo->errorstr  = _T("");
	p_datainfo->qt        = _T("");
	p_datainfo->quality   = 0;
	p_datainfo->checksum  = 0;
	p_datainfo->indexid   = 0;

    if(!chunk_size)
    {
        unsigned long long next_tag_ofs;
        AVIFindNextTag(&next_tag_ofs,nullptr);

        p_datainfo->chunksize = 
		chunk_size = next_tag_ofs - ofs;
    }

	jd = new JDEC;
	if(jd)
	{
		if(chunk_size)
		{
			jres = jd_fastcheck(jd,TjpgDecInput,this);
			p_datainfo->errorflag = jres;
			p_datainfo->errorstr.Format(_T("%s"),A2T(jd_geterrinfo(jd,jres)));
			
			for(qt_id = 0;qt_id < 2;qt_id++)
			{
				qt = jd_getqt(jd,qt_id);
				if(qt)
				{
					for(i = 0;i < 64;i++)
					{
						strQt.Format(_T("%u "),qt[i]);
						p_datainfo->qt += strQt;
					}
				}
				else
				{
					break;
				}
			}

			if(!chunk_size) jd->used_byte = 0;
			p_datainfo->datasize  = jd->used_byte;
			p_datainfo->quality   = (float)QuantTabQuality(jd_getqt(jd,0),0);
			p_datainfo->checksum  = 0;

			if(jres != JDR_OK)
			{
				CString strLog;
				strLog.Format(_T("[WARN] Decoder : %s (frame@0x%08I64x,error@0x%08I64x)"), (LPCWSTR)p_datainfo->errorstr,ofs,ofs + jd->used_byte);
				m_pLog->AddLineWarn(strLog);
			}
		}
		else
		{
			jres = JDR_ERR;
			p_datainfo->errorflag = JDR_ERR;
			p_datainfo->errorstr = _T("NO DATA");
			jd->used_byte = 
			p_datainfo->datasize  = 0;
			p_datainfo->quality   = 0;
			p_datainfo->checksum  = 0;
		}
	}
	else
	{
		ASSERT(jd);
	}
	
	while(chunk_size < jd->used_byte)
	{
		if(jres == JDR_OK)
		{
			//继续搜索下一个tag
			unsigned long long next_tag_ofs;
			int r = AVIFindNextTag(&next_tag_ofs,nullptr);

			p_datainfo->chunksize = 
			chunk_size = next_tag_ofs - ofs;

			if(r) break;
		}
		else
		{
			break;
		}
	}

	if(jd)	delete jd;
	seek(ofs + chunk_size);
    if(used) *used = chunk_size;
    return 0;
}

int CAviFile::AudioDataCheck(struct datainfo_s * p_audioinfo,unsigned long chunk_size,unsigned long *used)
{
	p_audioinfo->id        = 0;
	p_audioinfo->offset    = tell();
	p_audioinfo->chunksize = chunk_size;
	p_audioinfo->datasize  = 0;
	p_audioinfo->errorflag = 0;
	p_audioinfo->errorstr  = _T("NO ERROR");
	p_audioinfo->qt        = _T("");
	p_audioinfo->quality   = 0;
	p_audioinfo->checksum  = 0;
	p_audioinfo->indexid   = 0;

    unsigned long readsize = chunk_size;

    if(!chunk_size)
    {
        unsigned long long next_tag_ofs;
        if(AVIFindNextTag(&next_tag_ofs,nullptr))
        {
            //could not find tag
        }
        readsize = next_tag_ofs - tell();
    }

    skip(readsize);
    if(used) *used = readsize;
    return 0;
}

int CAviFile::MoviCheck(void)
{
	struct datainfo_s vdatainfo;
	struct datainfo_s adatainfo;
    CString strLog;// for check result
    strLog = _T("\n*** AVI MOVI Check Result ***\n");
    m_pLog->AddLineGood(strLog);

    if(m_nMoviOfs.empty())
    {
        strLog = _T("Could not find 'movi' chunk,nothing to do");
        m_pLog->AddLineGood(strLog);
    }
    else
    {
        unsigned int i;
        unsigned long long ofs;
        unsigned long tag;
        unsigned long used;
        unsigned long size,movi_size,MOVI_SIZE;
        unsigned long long movi_start_ofs;

        const unsigned long vtag = TAG('0','0'+m_bStreamNum[0],'d','c');
        const unsigned long atag = TAG('0','0'+m_bStreamNum[1],'w','b');

        for(i = 0;i < m_nMoviOfs.size();i++)
        {
			if(m_bNeedStop)
			{
				break;
			}

            if(seek(m_nMoviOfs[i]) != 0)
                continue;
            rl32();
            MOVI_SIZE =
            movi_size = rl32();movi_start_ofs = tell();
            rl32();movi_size -= 4;
            ofs = tell();
            while(ofs < (movi_start_ofs + MOVI_SIZE))
            {
				if(m_bNeedStop)
				{
					break;
				}

                ofs = tell();
                if(eof())
                {
                    strLog.Format(_T("[ERROR] Accidental eof @0x%08I64x"),ofs);
                    m_pLog->AddLineErr(strLog);
                    i = m_nMoviOfs.size();//break
                    break;
                }

                tag = rl32();
                size = rl32();
                movi_size -= 8;

                if(!movi_size)
                    strLog = _T("");

                if(size > movi_size)
                {
                    strLog.Format(_T("[ERROR] '%c%c%c%c' size too large @0x%08I64x,size is 0x%08x Byte"),UNFCC(tag),ofs,size);
                    m_pLog->AddLineErr(strLog);
                    size = movi_size;
                }
                else if(!size)
                {
                    strLog.Format(_T("[WARN] '%c%c%c%c' size is 0 @0x%08I64x"),UNFCC(tag),ofs);
                    m_pLog->AddLineWarn(strLog);
                }

				size = (size + 1) & ~1; //向上2对齐，ffmpeg生成的avi有这样的规则
                used = size;
                if(tag == vtag)
                {
                    VideoDataCheck(&vdatainfo,size,&used);
					SqlInsertData(m_strVDTabName,&vdatainfo,strLog);
                }
                else if(tag == atag)
                {
                    AudioDataCheck(&adatainfo,size,&used);
					SqlInsertData(m_strADTabName,&adatainfo,strLog);
                }
                else
                {
                    skip(size);
                }

                movi_size -= used;
                ofs = tell();
                strLog.Format(_T("#%d movi chunk check : %.2f%%"),i,(ofs - movi_start_ofs)*100.0/MOVI_SIZE);
                SetStatusText(strLog);
            }
        }
    }

	if(m_bNeedStop)
	{
		strLog = _T("USER STOP\n");
		m_pLog->AddLineGood(strLog);
	}

	SetStatusText(_T("Done"));
    return 0;
}

// ------------------------------------------------------------ 
// file io functions
// ------------------------------------------------------------
int CAviFile::r8()
{
    int r;
    BYTE nVal = 0;

    r = m_pFile->Read(&nVal,1);
    if(r != 1)
    {
        //TODO:deal with error
        return 0;
    }

    return nVal;
}

unsigned long CAviFile::rl16()
{
    unsigned long nVal;

    nVal  = r8();
    nVal |= r8() << 8;

    return nVal;
}

unsigned long CAviFile::rl32()
{
    unsigned long nVal;

    nVal  = rl16();
    nVal |= rl16() << 16;

    return nVal;
}

unsigned long CAviFile::read(unsigned char *dst,unsigned long cnt)
{
    return m_pFile->Read(dst,cnt);
}

int CAviFile::skip(long long ofs)
{
    int nVal = 0;

    try
    {
        m_pFile->Seek(ofs, CFile::current);
    }
    catch (CFileException* e)
    {
        TCHAR strMsg[MAX_BUF_EX_ERR_MSG];
        CString strError;
        e->GetErrorMessage(strMsg, MAX_BUF_EX_ERR_MSG);
        e->Delete();
        // Note: msg includes m_strPathName
        strError.Format(_T("ERROR: Couldn't seek file: [%s]"), strMsg);
        m_pLog->AddLineErr(strError);
        if (m_pAppConfig->bInteractive)
            AfxMessageBox(strError);
        nVal = -1;
    }

    return nVal;

}

int CAviFile::seek(unsigned long long ofs)
{
    int nVal = 0;
    try
    {
        m_pFile->Seek(ofs, CFile::begin);
    }
    catch (CFileException* e)
    {
        TCHAR strMsg[MAX_BUF_EX_ERR_MSG];
        CString strError;
        e->GetErrorMessage(strMsg, MAX_BUF_EX_ERR_MSG);
        e->Delete();
        // Note: msg includes m_strPathName
        strError.Format(_T("ERROR: Couldn't seek file: [%s]"), strMsg);
        m_pLog->AddLineErr(strError);
        if (m_pAppConfig->bInteractive)
            AfxMessageBox(strError);
        nVal = -1;
    }
    
    return nVal;
}

unsigned long long CAviFile::tell()
{
    return m_pFile->GetPosition();
}

/**
 * @brief 
 * @return 
 */
long long CAviFile::eof()
{
    return !(m_pFile->GetLength() - m_pFile->GetPosition());
}

unsigned int CAviFile::store(LPCTSTR pstrFileName,long long ofs,unsigned long size)
{
    const unsigned long buf_size = 4096;
    unsigned long read_size = 0;
    CFile file;
    BYTE * Buf = new BYTE[buf_size];

    if(Buf && !seek(ofs) && file.Open(pstrFileName,CFile::modeCreate|CFile::modeWrite))
    {
        while (size)
        {
            unsigned long readed = 0;
            unsigned long remain = min(buf_size,size);
            readed = m_pFile->Read(Buf,remain);

            file.Write(Buf,readed);
            read_size += readed;
            size -= readed;
            if(readed != remain)
                break;
        }

        file.Close();
        delete [] Buf;
    }

    return read_size;
}

CString * CAviFile::CheckOutputDir()
{
    //if(PathIsDirectory((LPCTSTR)m_strOutputPath))
    {
        if(!PathFileExists((LPCTSTR)m_strOutputPath))
        {
            if(!CreateDirectory((LPCTSTR)m_strOutputPath,NULL))
            {
                //TODO:处理错误

                return nullptr;
            }
        }
    }

    return &m_strOutputPath;
}

static UINT TjpgDecInput(JDEC* jd, BYTE* buff, UINT nbyte)
{
    CAviFile *dev = (CAviFile*)jd->device;   /* Device identifier for the session (5th argument of jd_prepare function) */

    if (buff) {
        /* Read bytes from input stream */
        return (UINT)dev->read(buff, nbyte);
    } else {
        /* Remove bytes from input stream */
        return dev->skip(nbyte) ? 0 : nbyte;
    }
}

static double QuantTabQuality(BYTE *qt,BYTE qt_id)
{
	bool	bQuantAllOnes = true;
	double	dComparePercent;
	double	dSumPercent=0;
	double	dSumPercentSqr=0;
	int		nDqtQuantDestId_Tq = qt_id;

	for (unsigned nCoeffInd=0;nCoeffInd<MAX_DQT_COEFF;nCoeffInd++)
	{
		unsigned short	nTmpVal2 = qt[nCoeffInd];

		if (nDqtQuantDestId_Tq == 0) {
			if (nTmpVal2 != 0) {
				dComparePercent = 100.0 *
					(double)(nTmpVal2) /
					(double)(glb_anStdQuantLum[glb_anZigZag[nCoeffInd]]);
			} else {
				dComparePercent = 999.99;
			}
		} else {
			if (nTmpVal2 != 0) {
				dComparePercent = 100.0 *
					(double)(nTmpVal2) /
					(double)(glb_anStdQuantChr[glb_anZigZag[nCoeffInd]]);
			} else {
				dComparePercent = 999.99;
			}
		}

		dSumPercent += dComparePercent;
		dSumPercentSqr += dComparePercent * dComparePercent;
		// Check just in case entire table are ones (Quality 100)
		if (nTmpVal2 != 1) bQuantAllOnes = 0;
	} // 0..63

	// Perform some statistical analysis of the quality factor
	// to determine the likelihood of the current quantization
	// table being a scaled version of the "standard" tables.
	// If the variance is high, it is unlikely to be the case.
	double	dQuality;
	double	dVariance;
	dSumPercent /= 64.0;	/* mean scale factor */
	dSumPercentSqr /= 64.0;
	dVariance = dSumPercentSqr - (dSumPercent * dSumPercent); /* variance */

	// Generate the equivalent IJQ "quality" factor
	if (bQuantAllOnes)		/* special case for all-ones table */
		dQuality = 100.0;
	else if (dSumPercent <= 100.0)
		dQuality = (200.0 - dSumPercent) / 2.0;
	else
		dQuality = 5000.0 / dSumPercent;

	return dQuality;
}

// ------------------------------------------------------------ 
// database functions
// ------------------------------------------------------------
const char SqlStrCreateDataTable[] = {
    "CREATE TABLE %s("
    "ID INTEGER PRIMARY KEY          ," //0
    "OFFSET         INT      NOT NULL," //1
    "CHUNKSIZE      INT      NOT NULL," //2
    "DATASIZE       INT      NOT NULL,"	//3
    "ERRORFLAG      INT      NOT NULL,"	//4
    "ERRORSTR       TEXT             ,"	//5
	"QTABLE         TEXT             ,"	//6
    "QUALITY        REAL     NOT NULL," //7 图像质量
    "CHECKSUM       INT      NOT NULL," //8
    "INDEXID        INT      NOT NULL "	//9
    ");"
};

const char SqlStrCreateIndexTable[] = {
    "CREATE TABLE %s("
    "ID INTEGER PRIMARY KEY          ," //0
    "OFFSET         INT      NOT NULL," //1
    "DATAOFFSET     INT      NOT NULL," //2
    "DATASIZE       INT      NOT NULL," //3
    "FLAG           INT      NOT NULL," //4
    "TIMECODE       CHAR(11) NOT NULL," //5 'hh:mm:ss:ff'
    "DATAID         INT      NOT NULL " //6
    ");"
};

#define  SqlCreateDataTable(pstrTabName,strErr)     SqlCreateTable(SqlStrCreateDataTable,pstrTabName,strErr)
#define  SqlCreateIndexTable(pstrTabName,strErr)    SqlCreateTable(SqlStrCreateIndexTable,pstrTabName,strErr)
int CAviFile::SqlCreateTable(const char * base_sql,LPCTSTR pstrTabName,CString &strErr)
{
    int res = 0;
    char * errmsg;
    
    CString strTabName = pstrTabName;
    int sqlen = strlen(base_sql) - 2 + strTabName.GetLength() + 1;
    char * sql = new char [sqlen];
    memset(sql,0,sqlen);
    
    USES_CONVERSION;
    char * name = T2A(strTabName);
    _snprintf_s(sql,sqlen,sqlen - 1,base_sql,name);

    if(sqlite3_exec(m_pDB,sql,NULL,NULL,&errmsg) != SQLITE_OK)
    {
        res = -1;
        strErr.Format(_T("Create table %s error : %s"),pstrTabName,A2T(errmsg));
		sqlite3_free(errmsg);
    }
    
    delete [] sql;
    return res;
}

int CAviFile::SqlInsertIndex(LPCTSTR pstrTabName,struct indexinfo_s * p_indexinfo,CString &strErr)
{
    static const char SqlStrInsertIndex[] = {
        "INSERT INTO %s VALUES "
        "(%s,   " // id
        "%llu,  " // index offset
        "%llu,  " // data offset
        "%u,    " // data size
        "%u,    " // frame flag
        "'%s',  " // timecode
        "%u     " // data id
        ");"
    };
    static char sql[512];
    static char timecode_buf[16];
    static char idbuf[16];
    unsigned int n = 0;
    int res = 0;
    char *errmsg = nullptr,*name;
    CString strTabName = pstrTabName;

    USES_CONVERSION;
    name = T2A(strTabName);
    
    timecode2cstr(p_indexinfo->timecode,timecode_buf);
    if(p_indexinfo->id)
    {
        n = _snprintf_s(idbuf,sizeof(idbuf),sizeof(idbuf) - 1,"%d",p_indexinfo->id);
        idbuf[n] = 0;
    }
    else
    {
        memcpy(idbuf,"NULL",5);
    }

    n = 
    _snprintf_s(sql,sizeof(sql),sizeof(sql) - 1,
                SqlStrInsertIndex,
                name,
                idbuf,
                p_indexinfo->offset,
                p_indexinfo->dataoffset,
                p_indexinfo->datasize,
                p_indexinfo->flags,
                timecode_buf,
                p_indexinfo->dataid
                );
    sql[n] = 0;
    
    if(sqlite3_exec(m_pDB,sql,NULL,NULL,&errmsg) != SQLITE_OK)
    {
        res = -1;
        strErr.Format(_T("Insert table %s error : %s"),pstrTabName,A2T(errmsg));
		sqlite3_free(errmsg);
    }

    return res;
}

int CAviFile::SqlInsertData(LPCTSTR pstrTabName,struct datainfo_s * p_datainfo,CString &strErr)
{
    static const char SqlStrInsertData[] = {
        "INSERT INTO %s VALUES "
        "(%s,   " // id
        "%llu,  " // chunk offset
        "%u,    " // chunk size
        "%u,    " // data size
        "%d,    " // error number
        "'%s',  " // error string
		"'%s',  " // quant table
        "%.2f,  " // quality
        "%u,    " // md5
        "%u     " // index id
        ");"
    };
    static char sql[1024];
    static char timecode_buf[16];
    static char idbuf[16];
    unsigned int n = 0;
    int res = 0;
    char *errmsg,*name;
    CString strTabName = pstrTabName;

    USES_CONVERSION;
    name = T2A(strTabName);
    
    if(p_datainfo->id)
    {
        n = _snprintf_s(idbuf,sizeof(idbuf),sizeof(idbuf) - 1,"%d",p_datainfo->id);
        idbuf[n] = 0;
    }
    else
    {
        memcpy(idbuf,"NULL",5);
    }

    n = 
    _snprintf_s(sql,sizeof(sql),sizeof(sql) - 1,
                SqlStrInsertData,
                name,
                idbuf,
                p_datainfo->offset,
                p_datainfo->chunksize,
                p_datainfo->datasize,
                p_datainfo->errorflag,
                T2A(p_datainfo->errorstr),
				T2A(p_datainfo->qt),
                p_datainfo->quality,
                p_datainfo->checksum,
                p_datainfo->indexid
                );
    sql[n] = 0;

    if(sqlite3_exec(m_pDB,sql,NULL,NULL,&errmsg) != SQLITE_OK)
    {
        res = -1;
        strErr.Format(_T("Insert table %s error : %s"),pstrTabName,A2T(errmsg));
		sqlite3_free(errmsg);
    }

    return res;
}

static int SqlSelectIndexCallBack(void*para , int nCount, char** pValue, char** pName)
{
    int res = -1;
    struct indexinfo_s * p_indexinfo = (struct indexinfo_s *)para;

    nCount = nCount;
    pName = pName;

    if(p_indexinfo)
    {
        p_indexinfo->id         = atoi(pValue[0]);
        p_indexinfo->offset     = atoi(pValue[1]);
        p_indexinfo->dataoffset = atoi(pValue[2]);
        p_indexinfo->datasize   = atoi(pValue[3]);
        p_indexinfo->flags      = atoi(pValue[4]);
        p_indexinfo->timecode   = cstr2timecode(pValue[5]);
        p_indexinfo->dataid     = atoi(pValue[6]);

        if(p_indexinfo->timecode != 0xffffffff)
            res = 0;
    }

    return res;
}

static int SqlSelectDataCallBack(void*para , int nCount, char** pValue, char** pName)
{
    int res = -1;
    struct datainfo_s * p_datainfo = (struct datainfo_s *)para;
	USES_CONVERSION;
    nCount = nCount;
    pName = pName;

    if(p_datainfo)
    {
        p_datainfo->id        = atoi(pValue[0]);
        p_datainfo->offset    = atoi(pValue[1]);
        p_datainfo->chunksize = atoi(pValue[2]);
        p_datainfo->datasize  = atoi(pValue[3]);
        p_datainfo->errorflag = atoi(pValue[4]);
        p_datainfo->errorstr.Format(_T("%s"),A2T(pValue[5]));
		p_datainfo->qt.Format(_T("%s"),A2T(pValue[6]));
        p_datainfo->quality   = (float)atof(pValue[7]);
        p_datainfo->checksum  = atoi(pValue[8]);
        p_datainfo->indexid   = atoi(pValue[9]);
    }
    res = 0;

    return res;
}

int CAviFile::SqlSelectId(int (*callback)(void*, int, char**, char**),
                        LPCTSTR pstrTabName,unsigned long id,void *para,CString &strErr)
{
    static const char SqlStrSelect[] = {
        "SELECT * FROM %s WHERE ID = %d;"
    };
    char sql[64];
    unsigned int n = 0;
    int res = 0;
    char *errmsg,*name;

    if(id)
    {
        USES_CONVERSION;
        name = T2A(pstrTabName);
        n = _snprintf_s(sql,sizeof(sql),sizeof(sql) - 1,SqlStrSelect,name,id);
        sql[n] = 0;

        if(sqlite3_exec(m_pDB,sql,callback,para,&errmsg) != SQLITE_OK)
        {
            res = -1;
            strErr.Format(_T("Select table %s error : %s"),pstrTabName,A2T(errmsg));
			sqlite3_free(errmsg);
        }
    }

    return res;
}

static void timecode2cstr(unsigned long timecode,char * buf)
{
    unsigned int time = timecode >> 16;
    unsigned int frame = timecode & 0xffff;

    if(buf)
    {
        if(frame > 99) frame = 99;
        unsigned int n = 
        sprintf_s(buf,12,
                "%02d:%02d:%02d|%02d",
                time / 3600,
                time % 3600 / 60,
                time % 3600 % 60,
                frame);
        buf[n] = 0;
    }
}

static unsigned long cstr2timecode(const char * cstr)
{
    unsigned long timecode = 0xffffffff;
    unsigned int time[3],frame,i;

    if(!cstr) goto out;
    if(strlen(cstr) != 11) goto out;

    i = _snscanf_s(cstr,11,"%02d:%02d:%02d|%02d",&time[0],&time[1],&time[2],&frame);
    if(i != 4) goto out;

    timecode = time[0] * 3600 + 
               time[1] * 60 + 
               time[2];
    timecode = (timecode << 16) | frame;

out:
    return timecode;
}

sqlite3* CAviFile::NewDB(LPCTSTR pDBName)
{
    pDBName = pDBName;
    CString strError;
    m_pDB = nullptr;

    if(sqlite3_open(":memory:",&m_pDB) != SQLITE_OK)
    {
        strError = _T("Could not create datebase!");
        if (m_pAppConfig->bInteractive)
            AfxMessageBox(strError);
        m_pDB = nullptr;
    }
    else
    {
        if(SqlCreateDataTable(m_strVDTabName,strError))
        {
            sqlite3_close(m_pDB);
            m_pDB = nullptr;
            goto out;
        }
        if(SqlCreateDataTable(m_strADTabName,strError))
        {
            sqlite3_close(m_pDB);
            m_pDB = nullptr;
            goto out;
        }
        if(SqlCreateIndexTable(m_strVITabName,strError))
        {
            sqlite3_close(m_pDB);
            m_pDB = nullptr;
            goto out;
        }
        if(SqlCreateIndexTable(m_strAITabName,strError))
        {
            sqlite3_close(m_pDB);
            m_pDB = nullptr;
            goto out;
        }

    }
out:
    return m_pDB;
}

int CAviFile::StoreDB2File(LPCTSTR pDBName)
{
	CString * pstrOutDir = CheckOutputDir();
	CString strError;

	if(m_pDB && pDBName && pstrOutDir)
	{
		USES_CONVERSION;
		int rc;
		char * destname;
		CString strDestName;
		sqlite3 * pDestFile;
		sqlite3_backup *pBackup;

		strDestName.Format(_T("%s%s.db"), (LPCWSTR)(*pstrOutDir), (LPCWSTR)pDBName);
        destname = T2A(strDestName);

		rc = sqlite3_open(destname, &pDestFile);
		if( rc == SQLITE_OK )
		{
			/* Set up the backup procedure to copy from the "main" database of 
			** connection pFile to the main database of connection pInMemory.
			** If something goes wrong, pBackup will be set to NULL and an error
			** code and  message left in connection pTo.
			**
			** If the backup object is successfully created, call backup_step()
			** to copy data from pFile to pInMemory. Then call backup_finish()
			** to release resources associated with the pBackup object.  If an
			** error occurred, then  an error code and message will be left in
			** connection pTo. If no error occurred, then the error code belonging
			** to pTo is set to SQLITE_OK.
			*/
			pBackup = sqlite3_backup_init(pDestFile, "main", m_pDB, "main");
			if( pBackup ){
				(void)sqlite3_backup_step(pBackup, -1);
				(void)sqlite3_backup_finish(pBackup);
			}
			rc = sqlite3_errcode(pDestFile);

			if(rc != SQLITE_OK)
			{
				strError.Format(_T("Store database error : %d"),rc);
				if (m_pAppConfig->bInteractive)
					AfxMessageBox(strError);
			}
		}
		else
		{
			strError = _T("Could not create datebase : ");
			strError += strDestName;
			if (m_pAppConfig->bInteractive)
				AfxMessageBox(strError);
		}

		(void)sqlite3_close(pDestFile);
	}

	return 0;
}
