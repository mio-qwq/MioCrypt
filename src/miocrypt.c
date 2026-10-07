#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <bcrypt.h>
#include <immintrin.h>
#include <intrin.h>
#include <strsafe.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "resource.h"
#include "rsa_public_blob.h"

#pragma comment(lib, "bcrypt.lib")

#define MAGIC_SIZE 8
#define SESSION_KEY_SIZE 8
#define MAXIMUM_FLAG_SIZE (16 * 1024 * 1024)

static const BYTE kMagic[MAGIC_SIZE] = {'M', 'I', 'O', 'C', 'R', 'Y', 'P', 'T'};

typedef struct ByteBuffer {
    BYTE* data;
    SIZE_T length;
} ByteBuffer;

static HINSTANCE gInstance;
static HBITMAP gBackgroundBitmap;
static HBITMAP gLockBitmap;

static int MinInt(int left, int right) {
    return left < right ? left : right;
}

static int MaxInt(int left, int right) {
    return left > right ? left : right;
}

static void ClearAndFree(ByteBuffer* buffer) {
    if (buffer->data != NULL) {
        SecureZeroMemory(buffer->data, buffer->length);
        HeapFree(GetProcessHeap(), 0, buffer->data);
    }
    buffer->data = NULL;
    buffer->length = 0;
}

static BOOL ReadFileBytes(const wchar_t* path, ByteBuffer* buffer) {
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER fileSize;
    DWORD bytesRead = 0;

    buffer->data = NULL;
    buffer->length = 0;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart < 0 || fileSize.QuadPart > MAXIMUM_FLAG_SIZE) {
        CloseHandle(file);
        return FALSE;
    }

    buffer->length = (SIZE_T)fileSize.QuadPart;
    buffer->data = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buffer->length == 0 ? 1 : buffer->length);
    if (buffer->data == NULL) {
        CloseHandle(file);
        return FALSE;
    }
    if (buffer->length != 0 && (!ReadFile(file, buffer->data, (DWORD)buffer->length, &bytesRead, NULL) || bytesRead != buffer->length)) {
        CloseHandle(file);
        ClearAndFree(buffer);
        return FALSE;
    }
    CloseHandle(file);
    return TRUE;
}

static BOOL WriteFileAtomically(const wchar_t* targetPath, const ByteBuffer* content) {
    HANDLE file = INVALID_HANDLE_VALUE;
    wchar_t* temporaryPath = NULL;
    SIZE_T temporaryPathLength = wcslen(targetPath) + wcslen(L".miocrypt.tmp") + 1;
    DWORD bytesWritten = 0;
    BOOL success = FALSE;

    temporaryPath = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, temporaryPathLength * sizeof(wchar_t));
    if (temporaryPath == NULL || FAILED(StringCchPrintfW(temporaryPath, temporaryPathLength, L"%s.miocrypt.tmp", targetPath))) {
        HeapFree(GetProcessHeap(), 0, temporaryPath);
        return FALSE;
    }

    file = CreateFileW(temporaryPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE &&
        (content->length == 0 || (WriteFile(file, content->data, (DWORD)content->length, &bytesWritten, NULL) && bytesWritten == content->length)) &&
        FlushFileBuffers(file)) {
        CloseHandle(file);
        file = INVALID_HANDLE_VALUE;
        success = MoveFileExW(temporaryPath, targetPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }
    if (!success) {
        DeleteFileW(temporaryPath);
    }
    HeapFree(GetProcessHeap(), 0, temporaryPath);
    return success;
}

static BOOL StartsWithMagic(const ByteBuffer* content) {
    return content->length >= MAGIC_SIZE && memcmp(content->data, kMagic, MAGIC_SIZE) == 0;
}

static BOOL GenerateSessionKey(BYTE sessionKey[SESSION_KEY_SIZE]) {
#if defined(_M_X64)
    int cpuInfo[4] = {0};
    unsigned __int64 randomValue = 0;
    int attempt;

    __cpuidex(cpuInfo, 1, 0);
    if ((cpuInfo[2] & (1 << 30)) != 0) {
        for (attempt = 0; attempt < 10; ++attempt) {
            if (_rdrand64_step(&randomValue) != 0) {
                memcpy(sessionKey, &randomValue, SESSION_KEY_SIZE);
                SecureZeroMemory(&randomValue, sizeof(randomValue));
                return TRUE;
            }
        }
    }
    SecureZeroMemory(&randomValue, sizeof(randomValue));
#endif
    return BCryptGenRandom(NULL, sessionKey, SESSION_KEY_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

static BOOL EncryptSessionKeyWithPublicKey(const BYTE sessionKey[SESSION_KEY_SIZE], ByteBuffer* encryptedKey) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE publicKey = NULL;
    BCRYPT_OAEP_PADDING_INFO paddingInfo;
    ULONG encryptedSize = 0;
    BOOL success = FALSE;

    encryptedKey->data = NULL;
    encryptedKey->length = 0;
    ZeroMemory(&paddingInfo, sizeof(paddingInfo));
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_RSA_ALGORITHM, NULL, 0) == 0 &&
        BCryptImportKeyPair(
            algorithm,
            NULL,
            BCRYPT_RSAPUBLIC_BLOB,
            &publicKey,
            (PUCHAR)kRsaPublicKeyBlob,
            (ULONG)kRsaPublicKeyBlobSize,
            0) == 0 &&
        BCryptEncrypt(
            publicKey,
            (PUCHAR)sessionKey,
            SESSION_KEY_SIZE,
            &paddingInfo,
            NULL,
            0,
            NULL,
            0,
            &encryptedSize,
            BCRYPT_PAD_OAEP) == 0) {
        encryptedKey->data = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, encryptedSize);
        encryptedKey->length = encryptedSize;
        if (encryptedKey->data != NULL &&
            BCryptEncrypt(
                publicKey,
                (PUCHAR)sessionKey,
                SESSION_KEY_SIZE,
                &paddingInfo,
                NULL,
                0,
                encryptedKey->data,
                encryptedSize,
                &encryptedSize,
                BCRYPT_PAD_OAEP) == 0) {
            encryptedKey->length = encryptedSize;
            success = TRUE;
        }
    }

    if (!success) {
        ClearAndFree(encryptedKey);
    }
    if (publicKey != NULL) {
        BCryptDestroyKey(publicKey);
    }
    if (algorithm != NULL) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    return success;
}

static void XorEncryptInPlace(ByteBuffer* plaintext, const BYTE sessionKey[SESSION_KEY_SIZE]) {
    SIZE_T index;
    for (index = 0; index < plaintext->length; ++index) {
        plaintext->data[index] ^= sessionKey[index % SESSION_KEY_SIZE];
    }
}

static BOOL EncryptFlagFile(const wchar_t* flagPath) {
    ByteBuffer plaintext = {0};
    ByteBuffer encryptedSessionKey = {0};
    ByteBuffer encryptedFile = {0};
    BYTE sessionKey[SESSION_KEY_SIZE] = {0};
    BOOL success = FALSE;

    if (!ReadFileBytes(flagPath, &plaintext) ||
        !GenerateSessionKey(sessionKey) ||
        !EncryptSessionKeyWithPublicKey(sessionKey, &encryptedSessionKey)) {
        goto cleanup;
    }

    XorEncryptInPlace(&plaintext, sessionKey);
    encryptedFile.length = MAGIC_SIZE + encryptedSessionKey.length + plaintext.length;
    encryptedFile.data = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, encryptedFile.length == 0 ? 1 : encryptedFile.length);
    if (encryptedFile.data == NULL) {
        goto cleanup;
    }
    memcpy(encryptedFile.data, kMagic, MAGIC_SIZE);
    memcpy(encryptedFile.data + MAGIC_SIZE, encryptedSessionKey.data, encryptedSessionKey.length);
    memcpy(encryptedFile.data + MAGIC_SIZE + encryptedSessionKey.length, plaintext.data, plaintext.length);
    success = WriteFileAtomically(flagPath, &encryptedFile);

cleanup:
    ClearAndFree(&plaintext);
    ClearAndFree(&encryptedSessionKey);
    ClearAndFree(&encryptedFile);
    SecureZeroMemory(sessionKey, sizeof(sessionKey));
    return success;
}

static HFONT CreateUiFont(int size, BOOL bold) {
    return CreateFontW(
        -size, 0, 0, 0, bold ? FW_BOLD : FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
}

static HFONT CreateMonoFont(int size, BOOL bold) {
    return CreateFontW(
        -size, 0, 0, 0, bold ? FW_BOLD : FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        FIXED_PITCH | FF_MODERN, L"Consolas");
}

static void DrawTextBlock(HDC deviceContext, const wchar_t* text, RECT rectangle, int size, COLORREF color, BOOL bold) {
    HFONT font = CreateUiFont(size, bold);
    HFONT previousFont = (HFONT)SelectObject(deviceContext, font);
    const int previousBackgroundMode = SetBkMode(deviceContext, TRANSPARENT);
    const COLORREF previousColor = SetTextColor(deviceContext, color);
    DrawTextW(deviceContext, text, -1, &rectangle, DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);
    SetTextColor(deviceContext, previousColor);
    SetBkMode(deviceContext, previousBackgroundMode);
    SelectObject(deviceContext, previousFont);
    DeleteObject(font);
}

static void DrawHeaderLockIcon(HDC deviceContext, int x, int y) {
    HBRUSH redBrush = CreateSolidBrush(RGB(230, 35, 48));
    HBRUSH blackBrush = CreateSolidBrush(RGB(14, 14, 14));
    HBRUSH ivoryBrush = CreateSolidBrush(RGB(247, 241, 222));
    RECT rectangle;

    /* The title-bar icon is drawn directly, so its surrounding area stays transparent. */
    rectangle = (RECT){x + 5, y + 2, x + 15, y + 4};
    FillRect(deviceContext, &rectangle, redBrush);
    rectangle = (RECT){x + 3, y + 4, x + 6, y + 10};
    FillRect(deviceContext, &rectangle, redBrush);
    rectangle = (RECT){x + 14, y + 4, x + 17, y + 10};
    FillRect(deviceContext, &rectangle, redBrush);
    rectangle = (RECT){x + 6, y + 4, x + 14, y + 9};
    FillRect(deviceContext, &rectangle, blackBrush);
    rectangle = (RECT){x + 3, y + 9, x + 17, y + 21};
    FillRect(deviceContext, &rectangle, redBrush);
    rectangle = (RECT){x + 5, y + 11, x + 15, y + 19};
    FillRect(deviceContext, &rectangle, blackBrush);
    rectangle = (RECT){x + 8, y + 12, x + 11, y + 14};
    FillRect(deviceContext, &rectangle, ivoryBrush);
    rectangle = (RECT){x + 11, y + 12, x + 14, y + 14};
    FillRect(deviceContext, &rectangle, ivoryBrush);
    rectangle = (RECT){x + 9, y + 14, x + 13, y + 16};
    FillRect(deviceContext, &rectangle, ivoryBrush);
    rectangle = (RECT){x + 10, y + 16, x + 12, y + 18};
    FillRect(deviceContext, &rectangle, ivoryBrush);
    DeleteObject(redBrush);
    DeleteObject(blackBrush);
    DeleteObject(ivoryBrush);
}

static int DrawSingleLine(HDC deviceContext, int x, int y, const wchar_t* text, int size, COLORREF color, BOOL bold, BOOL mono) {
    HFONT font = mono ? CreateMonoFont(size, bold) : CreateUiFont(size, bold);
    HFONT previousFont = (HFONT)SelectObject(deviceContext, font);
    SIZE textSize = {0};
    RECT textRectangle;
    int previousBackgroundMode = SetBkMode(deviceContext, TRANSPARENT);
    COLORREF previousColor = SetTextColor(deviceContext, color);

    GetTextExtentPoint32W(deviceContext, text, (int)wcslen(text), &textSize);
    textRectangle = (RECT){x, y, x + textSize.cx + 2, y + textSize.cy + 4};
    DrawTextW(deviceContext, text, -1, &textRectangle, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    SetTextColor(deviceContext, previousColor);
    SetBkMode(deviceContext, previousBackgroundMode);
    SelectObject(deviceContext, previousFont);
    DeleteObject(font);
    return x + textSize.cx;
}

static int DrawCodeChip(HDC deviceContext, int x, int y, const wchar_t* text) {
    const int horizontalPadding = 7;
    const int verticalPadding = 3;
    HFONT font = CreateMonoFont(15, FALSE);
    HFONT previousFont = (HFONT)SelectObject(deviceContext, font);
    SIZE textSize = {0};
    RECT chipRectangle;
    RECT textRectangle;
    HBRUSH chipBrush = CreateSolidBrush(RGB(52, 45, 31));
    int previousBackgroundMode = SetBkMode(deviceContext, TRANSPARENT);
    COLORREF previousColor = SetTextColor(deviceContext, RGB(249, 207, 115));

    GetTextExtentPoint32W(deviceContext, text, (int)wcslen(text), &textSize);
    chipRectangle = (RECT){x, y, x + textSize.cx + horizontalPadding * 2, y + textSize.cy + verticalPadding * 2};
    FillRect(deviceContext, &chipRectangle, chipBrush);
    DeleteObject(chipBrush);
    textRectangle = (RECT){x + horizontalPadding, y + verticalPadding - 1, chipRectangle.right, chipRectangle.bottom};
    DrawTextW(deviceContext, text, -1, &textRectangle, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    SetTextColor(deviceContext, previousColor);
    SetBkMode(deviceContext, previousBackgroundMode);
    SelectObject(deviceContext, previousFont);
    DeleteObject(font);
    return chipRectangle.right;
}

static void DrawBitmapPreservingAspect(HDC deviceContext, HBITMAP bitmap, int x, int y, int maximumWidth, int maximumHeight) {
    BITMAP bitmapInfo;
    HDC memoryContext;
    HGDIOBJ previousBitmap;
    double scale;
    int width;
    int height;

    if (bitmap == NULL || GetObjectW(bitmap, sizeof(bitmapInfo), &bitmapInfo) == 0) {
        return;
    }
    scale = ((double)maximumWidth / bitmapInfo.bmWidth) < ((double)maximumHeight / bitmapInfo.bmHeight)
        ? ((double)maximumWidth / bitmapInfo.bmWidth)
        : ((double)maximumHeight / bitmapInfo.bmHeight);
    width = (int)(bitmapInfo.bmWidth * scale);
    height = (int)(bitmapInfo.bmHeight * scale);
    memoryContext = CreateCompatibleDC(deviceContext);
    previousBitmap = SelectObject(memoryContext, bitmap);
    SetStretchBltMode(deviceContext, HALFTONE);
    StretchBlt(
        deviceContext,
        x + (maximumWidth - width) / 2,
        y + (maximumHeight - height) / 2,
        width,
        height,
        memoryContext,
        0,
        0,
        bitmapInfo.bmWidth,
        bitmapInfo.bmHeight,
        SRCCOPY);
    SelectObject(memoryContext, previousBitmap);
    DeleteDC(memoryContext);
}

static void ApplyRoundedWindowRegion(HWND window) {
    RECT windowRect;
    HRGN region;

    GetWindowRect(window, &windowRect);
    region = CreateRoundRectRgn(0, 0, windowRect.right - windowRect.left + 1, windowRect.bottom - windowRect.top + 1, 16, 16);
    if (region != NULL) {
        SetWindowRgn(window, region, TRUE);
    }
}

static void PaintMioCryptWindow(HWND window) {
    PAINTSTRUCT paint;
    RECT clientRect;
    HDC deviceContext = BeginPaint(window, &paint);
    HBRUSH backgroundBrush;
    HBRUSH headerBrush;
    HBRUSH redBrush;
    HBRUSH panelBrush;
    HBRUSH previousBrush;
    HPEN sealPen;
    HPEN previousPen;
    int windowWidth;
    int windowHeight;
    int imageX;
    int imageY;
    int imageWidth;
    int imageHeight;
    int textX;
    int currentX;
    RECT panelRectangle;
    RECT sealRectangle;

    GetClientRect(window, &clientRect);
    windowWidth = clientRect.right - clientRect.left;
    windowHeight = clientRect.bottom - clientRect.top;
    backgroundBrush = CreateSolidBrush(RGB(7, 10, 10));
    FillRect(deviceContext, &clientRect, backgroundBrush);
    DeleteObject(backgroundBrush);

    headerBrush = CreateSolidBrush(RGB(233, 226, 212));
    clientRect.top = 0;
    clientRect.bottom = 42;
    FillRect(deviceContext, &clientRect, headerBrush);
    DeleteObject(headerBrush);
    redBrush = CreateSolidBrush(RGB(230, 35, 48));
    clientRect.top = 42;
    clientRect.bottom = 46;
    FillRect(deviceContext, &clientRect, redBrush);
    DeleteObject(redBrush);

    DrawHeaderLockIcon(deviceContext, 18, 10);
    DrawSingleLine(deviceContext, 47, 12, L"MioCrypt", 16, RGB(25, 22, 22), FALSE, FALSE);
    DrawSingleLine(deviceContext, windowWidth - 84, 12, L"−", 16, RGB(48, 42, 40), FALSE, FALSE);
    DrawSingleLine(deviceContext, windowWidth - 57, 12, L"□", 14, RGB(48, 42, 40), FALSE, FALSE);
    DrawSingleLine(deviceContext, windowWidth - 29, 12, L"×", 16, RGB(48, 42, 40), FALSE, FALSE);

    imageX = windowWidth - 383;
    imageY = 86;
    imageWidth = 339;
    imageHeight = 290;
    if (imageX < 665) {
        imageX = windowWidth - imageWidth - 34;
    }
    panelRectangle = (RECT){imageX + 11, imageY + 10, imageX + imageWidth + 11, imageY + imageHeight + 10};
    panelBrush = CreateSolidBrush(RGB(79, 78, 76));
    FillRect(deviceContext, &panelRectangle, panelBrush);
    DeleteObject(panelBrush);
    DrawBitmapPreservingAspect(deviceContext, gBackgroundBitmap, imageX, imageY, imageWidth, imageHeight);
    redBrush = CreateSolidBrush(RGB(230, 35, 48));
    panelRectangle = (RECT){630, 322, 641, 492};
    FillRect(deviceContext, &panelRectangle, redBrush);
    DeleteObject(redBrush);

    textX = 66;
    DrawSingleLine(deviceContext, textX, 132, L"FLAG LOCKED / MIOCRYPT", 13, RGB(238, 42, 55), FALSE, TRUE);
    DrawSingleLine(deviceContext, textX + 3, 174, L"杂鱼～♡ 杂鱼～♡", 48, RGB(230, 35, 48), TRUE, FALSE);
    DrawSingleLine(deviceContext, textX, 169, L"杂鱼～♡ 杂鱼～♡", 48, RGB(241, 240, 229), TRUE, FALSE);
    DrawSingleLine(deviceContext, textX, 250, L"你的 flag 被 mio 酱加密了喵～", 18, RGB(239, 231, 207), FALSE, FALSE);

    panelRectangle = (RECT){66, 308, 630, 482};
    panelBrush = CreateSolidBrush(RGB(24, 27, 27));
    FillRect(deviceContext, &panelRectangle, panelBrush);
    DeleteObject(panelBrush);
    redBrush = CreateSolidBrush(RGB(230, 35, 48));
    panelRectangle = (RECT){76, 482, 641, 492};
    FillRect(deviceContext, &panelRectangle, redBrush);
    DeleteObject(redBrush);

    currentX = DrawSingleLine(deviceContext, 91, 340, L"请向地址 ", 16, RGB(244, 238, 218), FALSE, FALSE);
    currentX = DrawCodeChip(deviceContext, currentX + 4, 337, L"0xzakozakokfcthursdayvmio50");
    DrawSingleLine(deviceContext, currentX + 8, 340, L"发送一枚 $KFC，", 16, RGB(244, 238, 218), FALSE, FALSE);
    currentX = DrawSingleLine(deviceContext, 91, 387, L"再添加 mio 的 QQ：", 16, RGB(244, 238, 218), FALSE, FALSE);
    currentX = DrawCodeChip(deviceContext, currentX + 4, 384, L"1484417108");
    DrawSingleLine(deviceContext, currentX + 8, 387, L"获取“解密服务”喵～♡", 16, RGB(244, 238, 218), FALSE, FALSE);
    currentX = DrawSingleLine(deviceContext, 91, 432, L"别担心，本程序只会处理当前目录下的 ", 16, RGB(244, 238, 218), FALSE, FALSE);
    currentX = DrawCodeChip(deviceContext, currentX + 4, 429, L"flag");
    DrawSingleLine(deviceContext, currentX + 8, 432, L"文件。", 16, RGB(244, 238, 218), FALSE, FALSE);

    sealRectangle = (RECT){45, windowHeight - 144, 154, windowHeight - 35};
    redBrush = CreateSolidBrush(RGB(230, 35, 48));
    previousBrush = (HBRUSH)SelectObject(deviceContext, redBrush);
    Ellipse(deviceContext, sealRectangle.left + 10, sealRectangle.top + 8, sealRectangle.right + 10, sealRectangle.bottom + 8);
    SelectObject(deviceContext, previousBrush);
    DeleteObject(redBrush);
    sealPen = CreatePen(PS_SOLID, 1, RGB(239, 42, 55));
    previousPen = (HPEN)SelectObject(deviceContext, sealPen);
    SelectObject(deviceContext, GetStockObject(BLACK_BRUSH));
    Ellipse(deviceContext, sealRectangle.left, sealRectangle.top, sealRectangle.right, sealRectangle.bottom);
    SelectObject(deviceContext, previousPen);
    DeleteObject(sealPen);
    DrawSingleLine(deviceContext, 80, windowHeight - 112, L"FLAG", 14, RGB(244, 238, 218), FALSE, TRUE);
    DrawSingleLine(deviceContext, 62, windowHeight - 92, L"ENCRYPTED", 14, RGB(244, 238, 218), FALSE, TRUE);
    DrawSingleLine(deviceContext, 99, windowHeight - 71, L"♡", 13, RGB(244, 238, 218), FALSE, FALSE);

    DrawSingleLine(
        deviceContext,
        windowWidth - 349,
        windowHeight - 48,
        L"CTF SIMULATION — No real payment required.",
        11,
        RGB(217, 208, 183),
        FALSE,
        TRUE);
    EndPaint(window, &paint);
}

static LRESULT CALLBACK MioCryptWindowProcedure(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_NCHITTEST: {
        POINT point = {(int)(short)LOWORD(lParam), (int)(short)HIWORD(lParam)};
        RECT clientRect;
        GetClientRect(window, &clientRect);
        ScreenToClient(window, &point);
        if (point.y >= 0 && point.y < 42 && point.x < clientRect.right - 86) {
            return HTCAPTION;
        }
        return HTCLIENT;
    }
    case WM_LBUTTONUP: {
        int x = (int)(short)LOWORD(lParam);
        int y = (int)(short)HIWORD(lParam);
        RECT clientRect;
        GetClientRect(window, &clientRect);
        if (y >= 0 && y < 42) {
            if (x >= clientRect.right - 30) {
                DestroyWindow(window);
            } else if (x >= clientRect.right - 58) {
                ShowWindow(window, IsZoomed(window) ? SW_RESTORE : SW_MAXIMIZE);
            } else if (x >= clientRect.right - 86) {
                ShowWindow(window, SW_MINIMIZE);
            }
        }
        return 0;
    }
    case WM_SIZE:
        ApplyRoundedWindowRegion(window);
        InvalidateRect(window, NULL, TRUE);
        return 0;
    case WM_PAINT:
        PaintMioCryptWindow(window);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(window, message, wParam, lParam);
    }
}

static void ShowRansomWindow(void) {
    const wchar_t* className = L"MioCryptWindow";
    WNDCLASSW windowClass;
    HWND window;
    MSG message;
    int windowWidth = 1118;
    int windowHeight = 692;

    ZeroMemory(&windowClass, sizeof(windowClass));
    windowClass.hInstance = gInstance;
    windowClass.lpszClassName = className;
    windowClass.lpfnWndProc = MioCryptWindowProcedure;
    windowClass.hCursor = LoadCursorW(NULL, IDC_ARROW);
    windowClass.hIcon = (HICON)LoadImageW(gInstance, MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR);
    windowClass.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    RegisterClassW(&windowClass);

    window = CreateWindowExW(
        WS_EX_APPWINDOW, className, L"MioCrypt", WS_POPUP,
        (GetSystemMetrics(SM_CXSCREEN) - windowWidth) / 2,
        (GetSystemMetrics(SM_CYSCREEN) - windowHeight) / 2,
        windowWidth, windowHeight, NULL, NULL, gInstance, NULL);
    if (window == NULL) {
        return;
    }
    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);
    while (GetMessageW(&message, NULL, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}

static void ShowError(const wchar_t* message) {
    MessageBoxW(NULL, message, L"MioCrypt", MB_OK | MB_ICONERROR);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previousInstance, PWSTR commandLine, int showCommand) {
    wchar_t executablePath[32768] = {0};
    wchar_t* lastSlash;
    wchar_t flagPath[32768] = {0};
    ByteBuffer firstRead = {0};

    (void)previousInstance;
    (void)commandLine;
    (void)showCommand;
    /* The UI is laid out in physical pixels to match the fixed ransomware-style mockup. */
    SetProcessDPIAware();
    gInstance = instance;
    gBackgroundBitmap = LoadBitmapW(gInstance, MAKEINTRESOURCEW(IDB_BACKGROUND));
    gLockBitmap = LoadBitmapW(gInstance, MAKEINTRESOURCEW(IDB_LOCK));

    if (GetModuleFileNameW(NULL, executablePath, (DWORD)(sizeof(executablePath) / sizeof(executablePath[0]))) == 0 ||
        (lastSlash = wcsrchr(executablePath, L'\\')) == NULL) {
        ShowError(L"MioCrypt could not determine the executable directory.");
        goto cleanup;
    }
    *lastSlash = L'\0';
    if (FAILED(StringCchPrintfW(flagPath, sizeof(flagPath) / sizeof(flagPath[0]), L"%s\\flag", executablePath))) {
        ShowError(L"MioCrypt could not construct the flag path.");
        goto cleanup;
    }
    if (!ReadFileBytes(flagPath, &firstRead)) {
        ShowError(L"MioCrypt could not find or read a file named flag next to MioCrypt.exe.");
    } else if (StartsWithMagic(&firstRead)) {
        ClearAndFree(&firstRead);
        ShowRansomWindow();
    } else {
        ClearAndFree(&firstRead);
        if (!EncryptFlagFile(flagPath)) {
            ShowError(L"MioCrypt could not encrypt the flag file.");
        } else {
            ShowRansomWindow();
        }
    }

cleanup:
    ClearAndFree(&firstRead);
    DeleteObject(gBackgroundBitmap);
    DeleteObject(gLockBitmap);
    return 0;
}
