/*

maildir.hpp
-----------

Simple Maildir accessors (POSIX/Windows) without external dependencies.

*/

#pragma once

#include <chrono>
#include <fstream>
#include <random>
#include <set>
#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <atomic>

namespace mailxx::storage
{

class maildir
{
public:
    struct entry
    {
        std::filesystem::path path;
        std::string name;
        std::string flags;
    };

    explicit maildir(std::filesystem::path root)
        : root_(std::move(root)),
          tmp_dir_(root_ / "tmp"),
          new_dir_(root_ / "new"),
          cur_dir_(root_ / "cur")
    {
        std::filesystem::create_directories(tmp_dir_);
        std::filesystem::create_directories(new_dir_);
        std::filesystem::create_directories(cur_dir_);
    }

    std::vector<entry> list_new() const
    {
        return list_dir(new_dir_, false);
    }

    std::vector<entry> list_cur() const
    {
        return list_dir(cur_dir_, true);
    }

    std::string read_message(const entry& e) const
    {
        std::ifstream ifs(e.path, std::ios::binary);
        std::string out;
        ifs.seekg(0, std::ios::end);
        auto sz = ifs.tellg();
        if (sz > 0)
            out.resize(static_cast<std::size_t>(sz));
        ifs.seekg(0, std::ios::beg);
        ifs.read(out.data(), static_cast<std::streamsize>(out.size()));
        return out;
    }

    entry add_message(std::string_view rfc822) const
    {
        auto base = unique_name();
        auto tmp_path = tmp_dir_ / base;
        {
            std::ofstream ofs(tmp_path, std::ios::binary);
            ofs.write(rfc822.data(), static_cast<std::streamsize>(rfc822.size()));
        }
        auto dest_path = new_dir_ / base;
        std::filesystem::rename(tmp_path, dest_path);
        return {dest_path, dest_path.filename().string(), ""};
    }

    entry move_to_cur(const entry& e, std::string_view flags) const
    {
        auto clean = normalize_flags(flags);
        auto base = e.path.filename().string();
        auto dest_name = base + ":2," + clean;
        auto dest_path = cur_dir_ / dest_name;
        std::filesystem::rename(e.path, dest_path);
        return {dest_path, dest_name, clean};
    }

    entry set_flags(const entry& e, std::string_view flags) const
    {
        auto clean = normalize_flags(flags);
        auto base = base_name(e.path.filename().string());
        auto dest_name = base + ":2," + clean;
        auto dest_path = cur_dir_ / dest_name;
        if (dest_path == e.path)
            return {dest_path, dest_name, clean};
        std::filesystem::rename(e.path, dest_path);
        return {dest_path, dest_name, clean};
    }

private:
    static std::string normalize_flags(std::string_view flags)
    {
        static const std::set<char> allowed = {'D', 'F', 'P', 'R', 'S', 'T'};
        std::string out;
        for (char c : flags)
        {
            if (allowed.count(c) == 0)
                continue;
            if (out.find(c) == std::string::npos)
                out.push_back(c);
        }
        return out;
    }

    static std::string base_name(const std::string& filename)
    {
        auto pos = filename.find(":2,");
        if (pos == std::string::npos)
            return filename;
        return filename.substr(0, pos);
    }

    static std::string parse_flags(const std::string& filename)
    {
        auto pos = filename.find(":2,");
        if (pos == std::string::npos)
            return {};
        return filename.substr(pos + 3);
    }

    std::vector<entry> list_dir(const std::filesystem::path& dir, bool parse_flag) const
    {
        std::vector<entry> out;
        if (!std::filesystem::exists(dir))
            return out;
        for (const auto& de : std::filesystem::directory_iterator(dir))
        {
            if (!de.is_regular_file())
                continue;
            auto name = de.path().filename().string();
            std::string flags = parse_flag ? parse_flags(name) : "";
            out.push_back({de.path(), std::move(name), std::move(flags)});
        }
        return out;
    }

    static std::string unique_name()
    {
        static std::mt19937_64 rng(std::random_device{}());
        static std::atomic<uint64_t> counter{0};
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
        uint64_t rnd = rng();
        uint64_t cnt = ++counter;
        return std::to_string(ns) + "." + std::to_string(rnd) + "." + std::to_string(cnt);
    }

    std::filesystem::path root_;
    std::filesystem::path tmp_dir_;
    std::filesystem::path new_dir_;
    std::filesystem::path cur_dir_;
};

} // namespace mailxx::storage
