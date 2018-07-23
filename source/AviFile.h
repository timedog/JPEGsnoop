#pragma once

#include "DocLog.h"
#include "ImgDecode.h"
#include "DecodePs.h"
#include "DecodeDicom.h"
#include "WindowBuf.h"
#include "snoop.h"
#include "SnoopConfig.h"
#include "DbSigs.h"
#include <vector>
#ifndef FOURCC
#define FOURCC          DWORD
#endif

#include <MMSystem.h>
#include <aviriff.h>
#include "sqlite3.h"


struct datainfo_s;
struct indexinfo_s;

class CAviFile
{
public:
    CAviFile(CDocLog* pLog,CimgDecode* pImgDec);
    ~CAviFile();

public:
	int  Reset();
    BOOL LoadFile();
    int  CompletenessCheck();
    int  Stop();

	void SetStatusBar(CStatusBar* pStatBar);

public:
	unsigned long   	read(unsigned char *dst,unsigned long cnt);
    int                 skip(long long ofs);
private:
	// ----------------------------------------
	// AVI文件IO
	// ----------------------------------------
    int                 r8();
    unsigned long       rl16();
    unsigned long       rl32();
    int                 seek(unsigned long long ofs);
    unsigned long long  tell();
    long long           eof();
	unsigned int        store(LPCTSTR pstrFileName,long long ofs,unsigned long size);
	CString *           CheckOutputDir();
    // ----------------------------------------
	// 完整性检查
	// ----------------------------------------
    int          HeaderCheck();
    int          IndexScan();
	int			 MoviCheck();
    int          VideoDataCheck(struct datainfo_s * p_videodata,unsigned long chunk_size,unsigned long *used);
    int          AudioDataCheck(struct datainfo_s * p_audiodata,unsigned long chunk_size,unsigned long *used);
	int          OldIndexScan(unsigned long long index_start,unsigned long timecode_start,unsigned long *timecode_end);
	int          OdmlIndexScan();
	int          OdmlStdIndexScan(unsigned long long stdindx_start,unsigned long duration,unsigned long streamid,unsigned long timecode_start,unsigned long *timecode_end);

	void		 AVIStructPrintTag(CString &strDest,int nPreSpace,unsigned long nTag,unsigned long nSize,unsigned long nTag1,unsigned long long nPos);
	void	     AVIStructReadInfo(CString &strDest,int nPreSpace,unsigned long nSize);
	int          AVIFindNextTag(unsigned long long *ofs,unsigned long *tag);
	int          DataCheckSum(CString &strOut,unsigned long long start,unsigned long long len);

	// ----------------------------------------
	// 数据库
	// ----------------------------------------
	sqlite3*	 NewDB(LPCTSTR pDBName);
	int          StoreDB2File(LPCTSTR pDBName);
	int			 SqlInsertData(LPCTSTR pstrTabName,struct datainfo_s * p_datainfo,CString &strErr);
	int			 SqlInsertIndex(LPCTSTR pstrTabName,struct indexinfo_s * p_indexinfo,CString &strErr);
	int			 SqlCreateTable(const char *base_sql,LPCTSTR pstrTabName,CString &errmsg);
	int			 SqlSelectData(LPCTSTR pstrTabName,unsigned long id,struct datainfo_s * p_datainfo,CString &strErr);
	int          SqlSelectId(int (*callback)(void*, int, char**, char**),LPCTSTR pstrTabName,unsigned long id,void *para,CString &strErr);

	// ----------------------------------------
	// 输出信息
	// ----------------------------------------
	void         SetStatusText(CString strText);
private:
	// ----------------------------------------
	// 文件信息
	// ----------------------------------------
    CFile               *m_pFile;
	CString				m_strFileName;  //filetitle.avi
	CString				m_strFileTitle; //fitetitle
	CString				m_strOutputPath;

	// avi attribute
	std::vector<unsigned long long>   m_nMoviOfs;
	std::vector<unsigned long long>   m_nIdx1Ofs;
    BOOL                m_bIsOdml;
	BYTE				m_bStreamNum[2];//[0]表示video stream number
	unsigned long       m_nFrameRate;

    AVIMAINHEADER       *m_pAviMainHeader;
    AVIEXTHEADER        *m_pAviExtHeader;
    AVISTREAMHEADER     *m_pAviStreamVideoHeader;
    AVISTREAMHEADER     *m_pAviStreamAudioHeader;
    BITMAPINFOHEADER    *m_pAviStreamVideoFormat;
    WAVEFORMATEX        *m_pAviStreamAudioFormat;
	AVISUPERINDEX		*m_pAviVideoSuperIndex;
	AVISUPERINDEX		*m_pAviAudioSuperIndex;
	sqlite3				*m_pDB;

	// 数据库
	CString				 m_strVDTabName;
	CString				 m_strVITabName;
	CString				 m_strADTabName;
	CString				 m_strAITabName;

	// ----------------------------------------
	// 完整性检查的配置参数
	// ----------------------------------------
	BOOL				 m_bNeedStop;


	// ----------------------------------------
	// JPEGSnoop
	// ----------------------------------------

    // Configuration
    CSnoopConfig*       m_pAppConfig;
    bool                m_bVerbose;
    bool                m_bOutputDB;
    bool                m_bBufFakeDHT;      // Flag to redirect DHT read to AVI DHT over Buffer content

    // General classes required for decoding
    CimgDecode*         m_pImgDec;

    // UI elements & log
    CDocLog*            m_pLog;
    CStatusBar*			m_pStatBar;     // Link to status bar
};
