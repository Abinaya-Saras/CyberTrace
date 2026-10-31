import os
import hashlib
import time
import httpx

BASE_URL = "http://127.0.0.1:8000"

def run_chunked_upload_test(test_name: str, target_size_bytes: int, chunk_size_bytes: int, source_path: str):
    print(f"\n=======================================================")
    print(f"Starting {test_name}: Target Size = {target_size_bytes / (1024*1024):.2f} MB, Chunk Size = {chunk_size_bytes / (1024*1024):.2f} MB")
    print(f"=======================================================")

    temp_input_path = f"data/uploads/temp_{test_name}.log"
    os.makedirs("data/uploads", exist_ok=True)

    # 1. Prepare exact slice from source
    t0 = time.time()
    sha256 = hashlib.sha256()
    bytes_written = 0
    with open(source_path, "rb") as src, open(temp_input_path, "wb") as dst:
        while bytes_written < target_size_bytes:
            to_read = min(1024 * 1024, target_size_bytes - bytes_written)
            buf = src.read(to_read)
            if not buf:
                break
            dst.write(buf)
            sha256.update(buf)
            bytes_written += len(buf)

    orig_hash = sha256.hexdigest()
    actual_file_size = os.path.getsize(temp_input_path)
    prep_time = time.time() - t0
    print(f"Prepared test file: {actual_file_size:,} bytes in {prep_time:.2f}s")
    print(f"Original SHA-256: {orig_hash}")

    # 2. Init upload session
    client = httpx.Client(base_url=BASE_URL, timeout=60.0)
    upload_filename = f"verified_{test_name}.log"
    init_res = client.post("/api/upload/init", json={
        "filename": upload_filename,
        "total_size": actual_file_size,
        "chunk_size": chunk_size_bytes
    }).json()

    upload_id = init_res["upload_id"]
    total_chunks = init_res["total_chunks"]
    print(f"Initialized upload session '{upload_id}' ({total_chunks} chunks)")

    # 3. Stream chunks directly from temp_input_path
    upload_t0 = time.time()
    bytes_uploaded = 0

    with open(temp_input_path, "rb") as f:
        for chunk_idx in range(total_chunks):
            chunk_data = f.read(chunk_size_bytes)
            if not chunk_data:
                break
            res = client.post(
                "/api/upload/chunk",
                data={"upload_id": upload_id, "chunk_index": chunk_idx},
                files={"file": (f"chunk_{chunk_idx}.part", chunk_data, "application/octet-stream")}
            )
            assert res.status_code == 200, f"Chunk {chunk_idx} failed: {res.text}"
            bytes_uploaded += len(chunk_data)

    upload_duration = time.time() - upload_t0
    upload_speed_mb = (bytes_uploaded / (1024 * 1024)) / max(0.001, upload_duration)
    print(f"Uploaded {total_chunks} chunks ({bytes_uploaded:,} bytes) in {upload_duration:.2f}s ({upload_speed_mb:.1f} MB/s)")

    # 4. Status Check
    status_data = client.get(f"/api/upload/status/{upload_id}").json()
    assert status_data["is_complete"] is True, f"Upload status incomplete: {status_data}"
    assert status_data["received_count"] == total_chunks

    # 5. Finalize (trigger_pipeline=False to avoid running full correlation on raw slices)
    fin_t0 = time.time()
    fin_res = client.post("/api/upload/finalize", json={
        "upload_id": upload_id,
        "trigger_pipeline": False
    }).json()
    fin_time = time.time() - fin_t0

    final_path = fin_res["file_path"]
    saved_size = os.path.getsize(final_path)
    assert saved_size == actual_file_size, f"Size mismatch: expected {actual_file_size}, got {saved_size}"

    # 6. Checksum Verification
    hash_t0 = time.time()
    uploaded_sha256 = hashlib.sha256()
    with open(final_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            uploaded_sha256.update(chunk)
    uploaded_hash = uploaded_sha256.hexdigest()
    hash_time = time.time() - hash_t0

    print(f"Finalized in {fin_time:.3f}s. Checksum computed in {hash_time:.3f}s.")
    print(f"Uploaded SHA-256: {uploaded_hash}")
    assert uploaded_hash == orig_hash, f"CHECKSUM MISMATCH!\nExpected: {orig_hash}\nGot:      {uploaded_hash}"
    print(f"SUCCESS: {test_name} passed with 100% byte-for-byte SHA-256 match!")

    # Cleanup
    if os.path.exists(temp_input_path): os.remove(temp_input_path)
    if os.path.exists(final_path): os.remove(final_path)

    return {
        "test_name": test_name,
        "size_bytes": actual_file_size,
        "size_mb": round(actual_file_size / (1024 * 1024), 2),
        "chunk_size_mb": round(chunk_size_bytes / (1024 * 1024), 2),
        "chunks_count": total_chunks,
        "upload_seconds": round(upload_duration, 2),
        "throughput_mb_s": round(upload_speed_mb, 1),
        "sha256": uploaded_hash,
        "status": "PASSED"
    }

if __name__ == "__main__":
    results = []
    # Test 1: 10 MB (with 2 MB chunks)
    res_10m = run_chunked_upload_test(
        test_name="10MB_progressive_upload",
        target_size_bytes=10 * 1024 * 1024,
        chunk_size_bytes=2 * 1024 * 1024,
        source_path="firex-10G.log"
    )
    results.append(res_10m)

    # Test 2: 100 MB (with 16 MB chunks)
    res_100m = run_chunked_upload_test(
        test_name="100MB_progressive_upload",
        target_size_bytes=100 * 1024 * 1024,
        chunk_size_bytes=16 * 1024 * 1024,
        source_path="firex-10G.log"
    )
    results.append(res_100m)

    # Test 3: 500 MB (with 32 MB chunks)
    res_500m = run_chunked_upload_test(
        test_name="500MB_progressive_upload",
        target_size_bytes=500 * 1024 * 1024,
        chunk_size_bytes=32 * 1024 * 1024,
        source_path="firex-10G.log"
    )
    results.append(res_500m)

    print("\n=======================================================")
    print("PROGRESSIVE UPLOAD BENCHMARK SUMMARY")
    print("=======================================================")
    for r in results:
        print(f"Test: {r['test_name']:<25} | Size: {r['size_mb']:>6.1f} MB | Chunks: {r['chunks_count']:>3} | Time: {r['upload_seconds']:>5.2f}s | Speed: {r['throughput_mb_s']:>6.1f} MB/s | Result: {r['status']}")
